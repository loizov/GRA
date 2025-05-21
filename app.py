from flask import Flask, jsonify, request, redirect, url_for, render_template, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO, join_room, emit, leave_room
from dotenv import load_dotenv
import os
import uuid
import threading
import time
from datetime import datetime, timedelta
import logging
import random
import requests
import valve.rcon
from sqlalchemy.exc import OperationalError, DatabaseError

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Load environment variables
load_dotenv()

# Initialize application
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "sqlite:///gamematch.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)

# Serve Socket.IO client
@app.route('/static/socket.io.min.js')
def serve_socketio():
    return send_from_directory('static', 'socket.io.min.js')

# Steam API configuration
STEAM_API_KEY = os.getenv("STEAM_API_KEY")

# Constants
PLAYERS_PER_MATCH = 2  # Reduced for testing
ELO_INITIAL = 1000
ELO_K_FACTOR = 32
MAPS = ["de_dust2", "de_mirage", "de_inferno", "de_nuke", "de_overpass"]
SERVER_TOKEN = os.getenv("SERVER_TOKEN")
SERVERS = [
    {"id": 1, "ip": os.getenv("SERVER1_IP"), "status": "idle", "match_id": None},
    {"id": 2, "ip": os.getenv("SERVER2_IP"), "status": "idle", "match_id": None},
    {"id": 3, "ip": os.getenv("SERVER3_IP"), "status": "idle", "match_id": None}
]

# Database models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    steam_id = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    avatar_url = db.Column(db.String(200))
    elo = db.Column(db.Integer, default=ELO_INITIAL)
    matches_played = db.Column(db.Integer, default=0)
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    draws = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)

class Match(db.Model):
    __tablename__ = "matches"
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.String(36), unique=True, nullable=False)
    status = db.Column(db.String(20), default="pending")
    map_name = db.Column(db.String(50), nullable=False)
    server_id = db.Column(db.Integer, nullable=True)
    team1_score = db.Column(db.Integer, default=0)
    team2_score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)

class MatchPlayer(db.Model):
    __tablename__ = "match_players"
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.String(36), db.ForeignKey("matches.match_id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    team = db.Column(db.String(2), nullable=False)  # "T" or "CT"
    score = db.Column(db.Integer, default=0)
    kills = db.Column(db.Integer, default=0)
    deaths = db.Column(db.Integer, default=0)
    assists = db.Column(db.Integer, default=0)
    elo_change = db.Column(db.Integer, default=0)
    match = db.relationship("Match", backref="players")
    user = db.relationship("User", backref="matches")

class MatchQueue(db.Model):
    __tablename__ = "match_queue"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    map_preference = db.Column(db.String(50), default="random")
    match_type = db.Column(db.String(20), default="ranked")
    queue_time = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")

# Global variables for matchmaking queue
queue_lock = threading.Lock()
match_making_thread = None
match_making_active = False

# Helper functions
def is_authenticated():
    return "user_id" in session

def get_current_user():
    try:
        if is_authenticated():
            user = User.query.get(session["user_id"])
            return user if user else None
        return None
    except (OperationalError, DatabaseError) as e:
        app.logger.error(f"Database error in get_current_user: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error in get_current_user: {e}")
        return None

def calculate_elo_change(winner_team, loser_team, team1_players, team2_players):
    try:
        team1_avg_elo = sum([p.user.elo for p in team1_players]) / len(team1_players) if team1_players else ELO_INITIAL
        team2_avg_elo = sum([p.user.elo for p in team2_players]) / len(team2_players) if team2_players else ELO_INITIAL
        expected_score_team1 = 1 / (1 + 10 ** ((team2_avg_elo - team1_avg_elo) / 400))
        expected_score_team2 = 1 / (1 + 10 ** ((team1_avg_elo - team2_avg_elo) / 400))
        for player in team1_players:
            score_change = ELO_K_FACTOR * (1 - expected_score_team1) if winner_team == 1 else ELO_K_FACTOR * (0 - expected_score_team1)
            player.elo_change = int(score_change)
            player.user.elo += player.elo_change
            player.user.matches_played += 1
            player.user.wins += 1 if winner_team == 1 else 0
            player.user.losses += 1 if winner_team == 2 else 0
        for player in team2_players:
            score_change = ELO_K_FACTOR * (1 - expected_score_team2) if winner_team == 2 else ELO_K_FACTOR * (0 - expected_score_team2)
            player.elo_change = int(score_change)
            player.user.elo += player.elo_change
            player.user.matches_played += 1
            player.user.wins += 1 if winner_team == 2 else 0
            player.user.losses += 1 if winner_team == 1 else 0
    except Exception as e:
        app.logger.error(f"Error in calculate_elo_change: {e}")

def get_available_server():
    for server in SERVERS:
        if server["status"] == "idle":
            return server
    return None

def get_steam_user_details(steam_id):
    url = f"http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={STEAM_API_KEY}&steamids={steam_id}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        return {"player": data["response"]["players"][0]} if data["response"]["players"] else None
    except Exception as e:
        app.logger.error(f"Steam API error: {e}")
        return None

def require_server_token(f):
    def decorated(*args, **kwargs):
        token = request.headers.get("Server-Token")
        if not token or token != SERVER_TOKEN:
            return jsonify({"error": "Invalid or missing Server-Token"}), 401
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Routes
@app.route("/")
def index():
    try:
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        return render_template("index.html", user=user)
    except Exception as e:
        app.logger.error(f"Index route error: {e}")
        return jsonify({"error": "Failed to load index page"}), 500

@app.route("/queue")
def queue():
    try:
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        return render_template("queue.html", user=user)
    except Exception as e:
        app.logger.error(f"Queue route error: {e}")
        return jsonify({"error": "Failed to load queue page"}), 500

@app.route("/login")
def login():
    try:
        base_url = os.getenv("BASE_URL", "http://cs.csreforge.lol")
        return redirect(f"https://steamcommunity.com/openid/login?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.return_to={base_url}{url_for('authorize')}&openid.realm={base_url}{url_for('index')}&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select")
    except Exception as e:
        app.logger.error(f"Login route error: {e}")
        return jsonify({"error": "Failed to initiate Steam login"}), 500

@app.route("/authorize")
def authorize():
    try:
        params = request.args
        steam_id = params.get("openid.claimed_id", "").split("/")[-1]
        if not steam_id:
            app.logger.error("No SteamID in OpenID response")
            return redirect(url_for("index"))
        user_info = get_steam_user_details(steam_id)
        if not user_info:
            app.logger.error(f"Failed to fetch user info for SteamID: {steam_id}")
            return redirect(url_for("index"))
        user = User.query.filter_by(steam_id=steam_id).first()
        if not user:
            user = User(
                steam_id=steam_id,
                username=user_info["player"]["personaname"],
                avatar_url=user_info["player"]["avatarfull"]
            )
            db.session.add(user)
        else:
            user.username = user_info["player"]["personaname"]
            user.avatar_url = user_info["player"]["avatarfull"]
            user.last_login = datetime.utcnow()
        db.session.commit()
        session["user_id"] = user.id
        session["steam_id"] = steam_id
        app.logger.info(f"User {user.username} logged in")
        return redirect(url_for("index"))
    except Exception as e:
        app.logger.error(f"Authorize route error: {e}")
        return redirect(url_for("index"))

@app.route("/logout")
def logout():
    try:
        session.clear()
        app.logger.info("User logged out")
        return redirect(url_for("index"))
    except Exception as e:
        app.logger.error(f"Logout route error: {e}")
        return jsonify({"error": "Failed to logout"}), 500

@app.route("/profile/<int:user_id>")
def profile(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            app.logger.warning(f"User ID {user_id} not found")
            return jsonify({"error": "User not found"}), 404
        matches = MatchPlayer.query.filter_by(user_id=user_id).order_by(MatchPlayer.id.desc()).limit(10).all()
        return render_template("profile.html", user=user, matches=matches, current_user=get_current_user())
    except Exception as e:
        app.logger.error(f"Profile route error: {e}")
        return jsonify({"error": "Failed to load profile"}), 500

@app.route("/matches")
def matches():
    try:
        active_matches = Match.query.filter_by(status="active").order_by(Match.created_at.desc()).limit(10).all()
        completed_matches = Match.query.filter_by(status="completed").order_by(Match.ended_at.desc()).limit(10).all()
        return render_template("matches.html", active_matches=active_matches, completed_matches=completed_matches, user=get_current_user())
    except Exception as e:
        app.logger.error(f"Matches route error: {e}")
        return jsonify({"error": "Failed to load matches"}), 500

@app.route("/match/<string:match_id>")
def match_details(match_id):
    try:
        match = Match.query.filter_by(match_id=match_id).first()
        if not match:
            app.logger.warning(f"Match ID {match_id} not found")
            return jsonify({"error": "Match not found"}), 404
        players = MatchPlayer.query.filter_by(match_id=match_id).all()
        team1_players = [p for p in players if p.team == "T"]
        team2_players = [p for p in players if p.team == "CT"]
        server_ip = next((s["ip"] for s in SERVERS if s["id"] == match.server_id), None)
        spectate_url = f"steam://connect/{server_ip}/spectate" if server_ip else None
        return render_template("match_details.html", match=match, team1_players=team1_players, team2_players=team2_players, spectate_url=spectate_url, user=get_current_user())
    except Exception as e:
        app.logger.error(f"Match details route error: {e}")
        return jsonify({"error": "Failed to load match details"}), 500

@app.route("/leaderboard")
def leaderboard():
    try:
        top_players = User.query.order_by(User.elo.desc()).limit(100).all()
        return render_template("leaderboard.html", players=top_players, user=get_current_user())
    except Exception as e:
        app.logger.error(f"Leaderboard route error: {e}")
        return jsonify({"error": "Failed to load leaderboard"}), 500

@app.route("/api/queue/join", methods=["POST"])
def join_queue():
    try:
        if not is_authenticated():
            app.logger.warning("Unauthorized queue join attempt")
            return jsonify({"error": "Unauthorized"}), 401
        user_id = session["user_id"]
        data = request.json or {}
        map_preference = data.get("map", "random")
        match_type = data.get("match_type", "ranked")
        existing_queue = MatchQueue.query.filter_by(user_id=user_id).first()
        if existing_queue:
            app.logger.info(f"User {user_id} already in queue")
            return jsonify({"error": "Already in queue"}), 400
        queue_entry = MatchQueue(user_id=user_id, map_preference=map_preference, match_type=match_type)
        db.session.add(queue_entry)
        db.session.commit()
        start_matchmaking()
        app.logger.info(f"User {user_id} joined queue, matchmaking triggered")
        return jsonify({"status": "success", "message": "Joined queue, matchmaking started"})
    except Exception as e:
        app.logger.error(f"Queue join error: {e}")
        return jsonify({"error": "Failed to join queue"}), 500

@app.route("/api/queue/leave", methods=["POST"])
def leave_queue():
    try:
        if not is_authenticated():
            app.logger.warning("Unauthorized queue leave attempt")
            return jsonify({"error": "Unauthorized"}), 401
        user_id = session["user_id"]
        queue_entry = MatchQueue.query.filter_by(user_id=user_id).first()
        if queue_entry:
            db.session.delete(queue_entry)
            db.session.commit()
            app.logger.info(f"User {user_id} left queue")
        return jsonify({"status": "success", "message": "Left queue"})
    except Exception as e:
        app.logger.error(f"Queue leave error: {e}")
        return jsonify({"error": "Failed to leave queue"}), 500

@app.route("/api/match/accept", methods=["POST"])
def accept_match():
    try:
        if not is_authenticated():
            app.logger.warning("Unauthorized match accept attempt")
            return jsonify({"error": "Unauthorized"}), 401
        user_id = session["user_id"]
        match_id = request.json.get("match_id")
        match = Match.query.filter_by(match_id=match_id).first()
        if not match:
            app.logger.warning(f"Match {match_id} not found")
            return jsonify({"error": "Match not found"}), 404
        player = MatchPlayer.query.filter_by(match_id=match_id, user_id=user_id).first()
        if not player:
            app.logger.warning(f"User {user_id} not in match {match_id}")
            return jsonify({"error": "Not in this match"}), 403
        socketio.emit("player_accepted", {"user_id": user_id, "match_id": match_id}, room=f"match_{match_id}")
        app.logger.info(f"User {user_id} accepted match {match_id}")
        return jsonify({"status": "success", "message": "Match accepted"})
    except Exception as e:
        app.logger.error(f"Match accept error: {e}")
        return jsonify({"error": "Failed to accept match"}), 500

@app.route("/api/matches", methods=["GET"])
def api_matches():
    try:
        matches = Match.query.order_by(Match.created_at.desc()).limit(10).all()
        return jsonify([{
            "match_id": match.match_id,
            "map_name": match.map_name,
            "team1_score": match.team1_score,
            "team2_score": match.team2_score,
            "status": match.status,
            "created_at": match.created_at.isoformat() if match.created_at else None
        } for match in matches])
    except Exception as e:
        app.logger.error(f"API matches error: {e}")
        return jsonify({"error": "Failed to fetch matches"}), 500

@app.route("/api/online_users", methods=["GET"])
def api_online_users():
    try:
        recent_time = datetime.utcnow() - timedelta(minutes=10)
        online_users = User.query.filter(User.last_login >= recent_time).all()
        if not online_users:
            app.logger.warning("No online users found")
        return jsonify([{
            "id": user.id,
            "username": user.username,
            "elo": user.elo,
            "avatar_url": user.avatar_url
        } for user in online_users])
    except Exception as e:
        app.logger.error(f"API online users error: {e}")
        return jsonify({"error": "Failed to fetch online users"}), 500

@app.route("/api/server<int:server_id>/match/map", methods=["GET"])
@require_server_token
def get_server_map(server_id):
    try:
        if server_id not in [1, 2, 3]:
            app.logger.warning(f"Invalid server ID: {server_id}")
            return jsonify({"error": "Invalid server ID"}), 400
        server = next((s for s in SERVERS if s["id"] == server_id), None)
        if not server or not server["match_id"]:
            return jsonify({"status": "nomatch"})
        match = Match.query.filter_by(match_id=server["match_id"]).first()
        if not match:
            server["status"] = "idle"
            server["match_id"] = None
            return jsonify({"status": "nomatch"})
        if match.status in ["completed", "cancelled"]:
            server["status"] = "idle"
            server["match_id"] = None
            return jsonify({"status": "nomatch"})
        if match.status == "pending":
            return jsonify({"status": "nomap"})
        return jsonify({"status": match.map_name})
    except Exception as e:
        app.logger.error(f"Server map error: {e}")
        return jsonify({"error": "Failed to get server map"}), 500

@app.route("/api/server<int:server_id>/match/whitelist", methods=["GET"])
@require_server_token
def get_server_whitelist(server_id):
    try:
        if server_id not in [1, 2, 3]:
            app.logger.warning(f"Invalid server ID: {server_id}")
            return jsonify({"error": "Invalid server ID"}), 400
        server = next((s for s in SERVERS if s["id"] == server_id), None)
        if not server or not server["match_id"]:
            return jsonify({"status": "nomatch"})
        match = Match.query.filter_by(match_id=server["match_id"]).first()
        if not match:
            server["status"] = "idle"
            server["match_id"] = None
            return jsonify({"status": "nomatch"})
        if match.status in ["completed", "cancelled"]:
            server["status"] = "idle"
            server["match_id"] = None
            return jsonify({"status": "nomatch"})
        players = MatchPlayer.query.filter_by(match_id=server["match_id"]).all()
        whitelist = [{"steam_id": User.query.get(player.user_id).steam_id, "team": player.team} for player in players]
        return jsonify({"status": "whitelist", "players": whitelist})
    except Exception as e:
        app.logger.error(f"Server whitelist error: {e}")
        return jsonify({"error": "Failed to get whitelist"}), 500

@app.route("/api/server<int:server_id>/match/update", methods=["POST"])
@require_server_token
def server_match_update(server_id):
    try:
        if server_id not in [1, 2, 3]:
            app.logger.warning(f"Invalid server ID: {server_id}")
            return jsonify({"error": "Invalid server ID"}), 400
        data = request.json or {}
        match_id = data.get("match_id")
        status = data.get("status")
        team1_score = data.get("team1_score")
        team2_score = data.get("team2_score")
        player_stats = data.get("player_stats", [])
        match = Match.query.filter_by(match_id=match_id).first()
        if not match or match.server_id != server_id:
            app.logger.warning(f"Match {match_id} not found or not assigned to server {server_id}")
            return jsonify({"error": "Match not found or not assigned to this server"}), 404
        match.status = status if status else match.status
        match.team1_score = team1_score if team1_score is not None else match.team1_score
        match.team2_score = team2_score if team2_score is not None else match.team2_score
        if status == "completed":
            match.ended_at = datetime.utcnow()
            team1_players = MatchPlayer.query.filter_by(match_id=match_id, team="T").all()
            team2_players = MatchPlayer.query.filter_by(match_id=match_id, team="CT").all()
            for stats in player_stats:
                user_id = stats.get("user_id")
                player = MatchPlayer.query.filter_by(match_id=match_id, user_id=user_id).first()
                if player:
                    player.kills = stats.get("kills", 0)
                    player.deaths = stats.get("deaths", 0)
                    player.assists = stats.get("assists", 0)
                    player.score = stats.get("score", 0)
            winner_team = 1 if team1_score > team2_score else 2 if team2_score > team1_score else 0
            if winner_team:
                calculate_elo_change(winner_team, 3 - winner_team, team1_players, team2_players)
            else:
                for player in team1_players + team2_players:
                    player.user.matches_played += 1
                    player.user.draws += 1
            server = next(s for s in SERVERS if s["id"] == match.server_id)
            server["status"] = "idle"
            server["match_id"] = None
            db.session.commit()
            socketio.emit("match_completed", {"match_id": match_id}, room=f"match_{match_id}")
        db.session.commit()
        socketio.emit("match_update", {"match_id": match_id, "status": match.status, "team1_score": match.team1_score, "team2_score": match.team2_score}, room=f"match_{match_id}")
        app.logger.info(f"Match {match_id} updated for server {server_id}")
        return jsonify({"status": "success"})
    except Exception as e:
        app.logger.error(f"Server match update error: {e}")
        return jsonify({"error": "Failed to update match"}), 500

# Socket.IO events
@socketio.on("connect")
def handle_connect():
    try:
        if "user_id" in session:
            user_id = session["user_id"]
            join_room(f"user_{user_id}")
            emit("connection_status", {"status": "connected", "user_id": user_id}, room=f"user_{user_id}")
            app.logger.info(f"SocketIO connected for user {user_id}")
    except Exception as e:
        app.logger.error(f"SocketIO connect error: {e}")

@socketio.on("join_match_room")
def handle_join_match_room(data):
    try:
        match_id = data.get("match_id")
        if match_id:
            join_room(f"match_{match_id}")
            emit("joined_match_room", {"match_id": match_id}, room=f"match_{match_id}")
            app.logger.info(f"Joined match room {match_id}")
    except Exception as e:
        app.logger.error(f"Join match room error: {e}")

@socketio.on("leave_match_room")
def handle_leave_match_room(data):
    try:
        match_id = data.get("match_id")
        if match_id:
            leave_room(f"match_{match_id}")
            app.logger.info(f"Left match room {match_id}")
    except Exception as e:
        app.logger.error(f"Leave match room error: {e}")

@socketio.on("send_invite")
def handle_send_invite(data):
    try:
        from_user_id = data["from_user_id"]
        to_user_id = data["to_user_id"]
        from_user = User.query.get(from_user_id)
        if from_user and to_user_id:
            match_id = str(uuid.uuid4())
            socketio.emit("receive_invite", {
                "from_user_id": from_user_id,
                "from_username": from_user.username,
                "match_id": match_id
            }, room=f"user_{to_user_id}")
            app.logger.info(f"Invite sent from {from_user_id} to {to_user_id} for match {match_id}")
        else:
            app.logger.warning(f"Invalid user data for invite from {from_user_id} to {to_user_id}")
    except Exception as e:
        app.logger.error(f"Send invite error: {e}")

@socketio.on("accept_invite")
def handle_accept_invite(data):
    try:
        match_id = data["match_id"]
        user_id = data["user_id"]
        match = Match.query.filter_by(match_id=match_id).first() or Match(match_id=match_id, status="lobby", created_at=datetime.utcnow())
        db.session.add(match) if not match.id else None
        player = MatchPlayer(match_id=match_id, user_id=user_id, team="T")
        db.session.add(player)
        db.session.commit()
        socketio.emit("invite_accepted", {
            "match_id": match_id,
            "user_id": user_id
        }, room=f"match_{match_id}")
        app.logger.info(f"User {user_id} accepted invite for match {match_id}")
    except Exception as e:
        app.logger.error(f"Accept invite error: {e}")

# Matchmaking functions
def start_matchmaking():
    global match_making_thread, match_making_active
    try:
        with queue_lock:
            if match_making_thread is None or not match_making_thread.is_alive():
                match_making_active = True
                match_making_thread = threading.Thread(target=matchmaking_process, daemon=True)
                match_making_thread.start()
                app.logger.info("Matchmaking thread started")
    except Exception as e:
        app.logger.error(f"Start matchmaking error: {e}")

def matchmaking_process():
    global match_making_active
    app.logger.info("Matchmaking process started")
    while match_making_active:
        try:
            with app.app_context():
                queue_size = MatchQueue.query.count()
                app.logger.info(f"Current queue size: {queue_size}")
                if queue_size >= PLAYERS_PER_MATCH:
                    with queue_lock:
                        queue_entries = MatchQueue.query.order_by(MatchQueue.queue_time).limit(PLAYERS_PER_MATCH).all()
                        if len(queue_entries) >= PLAYERS_PER_MATCH:
                            map_votes = {}
                            match_type = queue_entries[0].match_type
                            for entry in queue_entries:
                                if entry.match_type != match_type:
                                    continue
                                if entry.map_preference != "random":
                                    map_votes[entry.map_preference] = map_votes.get(entry.map_preference, 0) + 1
                            chosen_map = max(map_votes.items(), key=lambda x: x[1])[0] if map_votes else random.choice(MAPS)
                            player_ids = [entry.user_id for entry in queue_entries]
                            for entry in queue_entries:
                                db.session.delete(entry)
                            db.session.commit()
                            match_id = create_match(player_ids, chosen_map)
                            if match_id:
                                for user_id in player_ids:
                                    socketio.emit("match_found", {
                                        "match_id": match_id,
                                        "map": chosen_map,
                                        "match_type": match_type
                                    }, room=f"user_{user_id}")
                                    socketio.emit("match_found_notification", {
                                        "match_id": match_id,
                                        "message": "Match found! Waiting for players..."
                                    }, room=f"user_{user_id}")
                            else:
                                app.logger.error("Failed to create match")
                                for user_id in player_ids:
                                    new_entry = MatchQueue(user_id=user_id, map_preference="random", match_type=match_type)
                                    db.session.add(new_entry)
                                db.session.commit()
                time.sleep(2)  # Faster check for testing
        except Exception as e:
            app.logger.error(f"Error in matchmaking process: {e}")
            time.sleep(2)

def create_match(player_ids, map_name):
    try:
        server = get_available_server()
        if not server:
            app.logger.error("No available servers")
            return None
        match_id = str(uuid.uuid4())
        match = Match(
            match_id=match_id,
            status="pending",
            map_name=map_name,
            server_id=server["id"],
            created_at=datetime.utcnow()
        )
        db.session.add(match)
        users = User.query.filter(User.id.in_(player_ids)).all()
        users.sort(key=lambda x: x.elo, reverse=True)
        team1_ids = [users[i].id for i in range(0, PLAYERS_PER_MATCH, 2)]
        team2_ids = [users[i].id for i in range(1, PLAYERS_PER_MATCH, 2)]
        for user_id in team1_ids:
            player = MatchPlayer(match_id=match_id, user_id=user_id, team="T")
            db.session.add(player)
        for user_id in team2_ids:
            player = MatchPlayer(match_id=match_id, user_id=user_id, team="CT")
            db.session.add(player)
        server["status"] = "busy"
        server["match_id"] = match_id
        db.session.commit()
        threading.Thread(target=setup_match_server, args=(match_id, map_name, server["id"]), daemon=True).start()
        app.logger.info(f"Match {match_id} created on server {server['id']}")
        return match_id
    except Exception as e:
        app.logger.error(f"Error creating match: {e}")
        return None

def setup_match_server(match_id, map_name, server_id):
    try:
        with app.app_context():
            match = Match.query.filter_by(match_id=match_id).first()
            if not match:
                app.logger.error(f"Match {match_id} not found")
                return
            server = next(s for s in SERVERS if s["id"] == server_id)
            server_ip, server_port = server["ip"].split(":")
            server_port = int(server_port)
            rcon_password = os.getenv("RCON_PASSWORD", "default_rcon_password")
            players = MatchPlayer.query.filter_by(match_id=match_id).all()
            player_steam_ids = [User.query.get(p.user_id).steam_id for p in players]
            send_rcon_command(server_ip, server_port, rcon_password, f"add_players {','.join(player_steam_ids)}")
            match.status = "active"
            match.started_at = datetime.utcnow()
            db.session.commit()
            for player in match.players:
                socketio.emit("server_ready", {
                    "match_id": match_id,
                    "server_ip": server["ip"],
                    "map_name": map_name
                }, room=f"user_{player.user_id}")
            app.logger.info(f"Server setup complete for match {match_id}")
    except Exception as e:
        app.logger.error(f"Error setting up match server: {e}")
        server = next(s for s in SERVERS if s["id"] == server_id)
        server["status"] = "idle"
        server["match_id"] = None
        match.status = "cancelled"
        db.session.commit()
        for player in match.players:
            socketio.emit("match_cancelled", {
                "match_id": match_id,
                "reason": "Server setup failed"
            }, room=f"user_{player.user_id}")

def send_rcon_command(server_ip, port, rcon_password, command):
    try:
        with valve.rcon.RCON((server_ip, port), rcon_password) as rcon:
            rcon.execute(command)
        app.logger.info(f"RCON command sent: {command}")
    except Exception as e:
        app.logger.error(f"RCON command failed: {e}")

# Initialize database
with app.app_context():
    try:
        db.create_all()
        app.logger.info("Database tables created")
    except Exception as e:
        app.logger.error(f"Failed to create database tables: {e}")

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=80, debug=True)