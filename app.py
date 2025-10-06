# =============================
# Imports
# =============================
import os
import functools
import traceback
import json
import requests
from bs4 import BeautifulSoup
import google.generativeai as genai
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, redirect, url_for, request, session, flash
from dotenv import load_dotenv
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from sqlalchemy import func

# Load environment variables from .env file at the very beginning
load_dotenv()

# =============================
# App Initialization & Configuration
# =============================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'devkey')
# Configure Gemini AI
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# =============================
# Database Models
class Competitor(db.Model):
    __tablename__ = 'competitor'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class CompetitorArticle(db.Model):
    __tablename__ = 'competitor_article'
    id = db.Column(db.Integer, primary_key=True)
    competitor_id = db.Column(db.Integer, db.ForeignKey('competitor.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    published_at = db.Column(db.String(50))
    improvement_brief = db.Column(db.Text)
# =============================

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)


class Keyword(db.Model):
    __tablename__ = 'keyword'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class FoundPost(db.Model):
    __tablename__ = 'found_post'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(120))
    subreddit = db.Column(db.String(120))
    permalink = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    intent = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())


class SavedReply(db.Model):
    __tablename__ = 'saved_reply'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # =============================
    # Helper Functions (Email, Auth Decorator)
    # =============================

    def login_required(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    # =============================
    # Action Items Route (after app initialization and models)
    # =============================



def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =============================
# Action Items Route (after app initialization and models)
# =============================

@app.route('/action-items', methods=['GET', 'POST'])
@login_required
def action_items():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    # Action items: FoundPosts flagged by the user for action
    action_items = FoundPost.query.filter_by(user_id=user_id, intent='Action').order_by(FoundPost.id.desc()).all()
    completed_items = FoundPost.query.filter_by(user_id=user_id, intent='Completed').order_by(FoundPost.id.desc()).all()
    if request.method == 'POST':
        post_id = request.form.get('complete_id')
        if post_id:
            post = db.session.get(FoundPost, int(post_id))
            if post and post.user_id == user_id and post.intent == 'Action':
                post.intent = 'Completed'
                db.session.commit()
                flash('Marked as complete.')
            return redirect(url_for('action_items'))
    return render_template('action_items.html', user=user, action_items=action_items, completed_items=completed_items)

# =============================
# Helper Functions (Email, Auth Decorator)
# =============================

def send_email_alert(subject, recipient, body):
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = os.getenv('BREVO_API_KEY')
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
    sender = {"email": os.getenv("SENDER_EMAIL"), "name": "Mention Monitor"}
    to = [{"email": recipient}]
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, sender=sender, subject=subject, html_content=body)
    try:
        api_instance.send_transac_email(send_smtp_email)
        print(f"Email sent to {recipient}!")
    except ApiException as e:
        print(f"Error sending email: {e}")

def register_step1_url():
    if request.method == 'POST':
        url = request.form['website_url']
        # Gemini API call to scrape and profile
        business_profile, suggested_keywords = get_gemini_profile(url)
        session['website_url'] = url
        session['business_profile'] = business_profile
        session['suggested_keywords'] = suggested_keywords
        return redirect(url_for('register_step2_review'))
    return render_template('register_step1_url.html')

def register_step2_review():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        keywords = request.form.getlist('keywords')[:3]
        user = User(email=email, password=password, keywords=keywords, website_url=session.get('website_url'), business_profile=session.get('business_profile'))
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    return render_template('register_step2_review.html', business_profile=session.get('business_profile'), suggested_keywords=session.get('suggested_keywords'))


# =============================
# Routes
@app.route('/competitor-watch', methods=['GET', 'POST'])
@login_required
def competitor_watch():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    # Add/remove competitors
    if request.method == 'POST':
        blog_url = request.form.get('blog_url')
        remove_id = request.form.get('remove_id')
        improve_id = request.form.get('improve_id')
        if blog_url:
            competitor = Competitor(url=blog_url, user_id=user_id)
            db.session.add(competitor)
            db.session.commit()
            flash('Competitor added.')
        elif remove_id:
            competitor = db.session.get(Competitor, int(remove_id))
            if competitor and competitor.user_id == user_id:
                db.session.delete(competitor)
                db.session.commit()
                flash('Competitor removed.')
        elif improve_id:
            article = db.session.get(CompetitorArticle, int(improve_id))
            if article:
                # AI teardown for improvement brief
                prompt = (
                    f"Analyze this blog post. Identify its weaknesses, find gaps in its information, and generate a brief for a '10x better' version of this article that is more detailed, helpful, and up-to-date.\n\nArticle Content:\n{article.title} - {article.url}"
                )
                try:
                    model = genai.GenerativeModel('gemini-2.5-flash')
                    response = model.generate_content(prompt)
                    article.improvement_brief = response.text.strip()
                    db.session.commit()
                    flash('Improvement brief generated.')
                except Exception as e:
                    traceback.print_exc()
                    flash('AI generation failed.')
        return redirect(url_for('competitor_watch'))
    competitors = Competitor.query.filter_by(user_id=user_id).all()
    articles = CompetitorArticle.query.join(Competitor).filter(Competitor.user_id == user_id).order_by(CompetitorArticle.id.desc()).all()
    return render_template('competitor_watch.html', user=user, competitors=competitors, articles=articles)
@app.route('/ai-generator', methods=['GET', 'POST'])
@login_required
def ai_generator():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    ai_content = None
    if request.method == 'POST':
        title = request.form.get('title')
        if not title:
            flash('Please enter a topic for AI generation.')
            return redirect(url_for('ai_generator'))
        prompt = (
            f"You are a helpful community manager. Write a concise, friendly, and authentic-sounding Reddit comment about the topic: '{title}'. "
            "The comment should be helpful and not sound like a corporate advertisement. Do not include a greeting or a sign-off."
        )
        try:
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = model.generate_content(prompt)
            ai_content = response.text.strip()
        except Exception as e:
            traceback.print_exc()
            flash('AI generation failed.')
    return render_template('ai_generator.html', user=user, ai_content=ai_content)
# =============================
@app.route('/lead-board', methods=['GET', 'POST'])
@login_required
def lead_board():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    high_intent_labels = ['Buying Question', 'Competitor Complaint', 'Support Request']
    # Status options: To Do, Contacted, Won
    if request.method == 'POST':
        post_id = request.form.get('post_id')
        new_status = request.form.get('status')
        post = db.session.get(FoundPost, int(post_id)) if post_id else None
        if post and post.user_id == user_id and new_status in ['To Do', 'Contacted', 'Won']:
            post.intent = new_status
            db.session.commit()
            flash('Status updated.')
        return redirect(url_for('lead_board'))
    # Only show posts with high-intent labels or status (To Do, Contacted, Won)
    posts = FoundPost.query.filter(
        FoundPost.user_id == user_id,
        FoundPost.intent.in_(high_intent_labels + ['To Do', 'Contacted', 'Won'])
    ).order_by(FoundPost.id.desc()).all()
    saved_replies_objs = SavedReply.query.filter_by(user_id=user_id).order_by(SavedReply.id.desc()).all()
    saved_replies = [{"title": reply.title, "content": reply.content} for reply in saved_replies_objs]
    return render_template('lead_board.html', user=user, posts=posts, replies=saved_replies)
@app.route('/')
def home():
    import datetime
    year = datetime.datetime.now().year
    return render_template('index.html', year=year)

@app.route('/register')
def register():
    return render_template('register_step1_url.html')

@app.route('/register_step2_review')
def register_step2_review():
    return render_template('register_step2_review.html')

@app.route('/register/complete', methods=['POST'])
def register_complete():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    keywords = request.form.getlist('keywords[]')
    keywords_for_free_plan = keywords[:3]
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        flash('Username or email already exists. Please log in.')
        return redirect(url_for('login'))
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    for kw in keywords_for_free_plan:
        if kw.strip():
            keyword_obj = Keyword(text=kw.strip(), user_id=new_user.id)
            db.session.add(keyword_obj)
    db.session.commit()
    flash('Account created successfully! Please log in.')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard_redirect')) # Changed to redirect
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

# New /dashboard redirect route
@app.route('/dashboard')
@login_required
def dashboard_redirect():
    return redirect(url_for('reddit_monitor'))

@app.route('/reddit/monitor', methods=['GET', 'POST'])
@login_required
def reddit_monitor():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    if user is None:
        flash('User not found. Please log in again.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        keyword_text = request.form.get('keyword')
        if keyword_text:
            user_plan = getattr(user, 'plan', 'free')
            if user_plan == 'free':
                keyword_count = Keyword.query.filter_by(user_id=user_id).count()
                if keyword_count >= 3:
                    flash('You have reached your 3 keyword limit. Please upgrade to add more.')
                    return redirect(url_for('reddit_monitor'))
            new_keyword = Keyword(text=keyword_text, user_id=user_id)
            db.session.add(new_keyword)
            db.session.commit()
        return redirect(url_for('reddit_monitor'))
    user_keywords = Keyword.query.filter_by(user_id=user_id).all()
    found_posts = FoundPost.query.filter_by(user_id=user_id).order_by(FoundPost.id.desc()).all()
    saved_replies_objs = SavedReply.query.filter_by(user_id=user_id).order_by(SavedReply.id.desc()).all()
    saved_replies = [{"title": reply.title, "content": reply.content} for reply in saved_replies_objs]
    return render_template('reddit_monitor.html', user=user, keywords=user_keywords, posts=found_posts, replies=saved_replies)

@app.route('/delete_keyword/<int:keyword_id>', methods=['POST'])
@login_required
def delete_keyword(keyword_id):
    user_id = session['user_id']
    keyword = db.session.get(Keyword, keyword_id)
    if keyword and keyword.user_id == user_id:
        db.session.delete(keyword)
        db.session.commit()
        flash('Keyword deleted.')
    else:
        flash('Keyword not found or unauthorized.')
    return redirect(url_for('reddit_monitor')) # Corrected redirect

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not bcrypt.check_password_hash(user.password, current_password):
            flash('Incorrect current password.')
            return redirect(url_for('settings'))
        if not new_password or new_password != confirm_password:
            flash('New passwords do not match or are empty.')
            return redirect(url_for('settings'))
        hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_new_password
        db.session.commit()
        flash('Your password has been updated successfully!')
        return redirect(url_for('dashboard_redirect')) # Corrected redirect
    return render_template('settings.html', user=user)

@app.route('/reddit/ai-agent', methods=['GET', 'POST'])
@login_required
def reddit_ai_agent():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    # Handle create, edit, delete, and AI generation
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'generate':
            # AI Generator: Generate reply draft from topic
            title = request.form.get('title')
            if not title:
                flash('Please enter a topic for AI generation.')
                return redirect(url_for('reddit_ai_agent'))
            prompt = (
                f"You are a helpful community manager. Write a concise, friendly, and authentic-sounding Reddit comment about the topic: '{title}'. "
                "The comment should be helpful and not sound like a corporate advertisement. Do not include a greeting or a sign-off."
            )
            try:
                model = genai.GenerativeModel('gemini-2.5-flash')
                response = model.generate_content(prompt)
                generated_text = response.text.strip()
                return render_template('reddit_ai_agent.html', replies=SavedReply.query.filter_by(user_id=user_id).order_by(SavedReply.id.desc()).all(), user=user, ai_title=title, ai_content=generated_text)
            except Exception as e:
                traceback.print_exc()
                flash('AI generation failed.')
                return redirect(url_for('reddit_ai_agent'))
        elif action == 'save':
            # Save new reply (from AI or manual)
            title = request.form.get('title')
            content = request.form.get('content')
            if title and content:
                reply = SavedReply(title=title, content=content, user_id=user_id)
                db.session.add(reply)
                db.session.commit()
                flash('Reply saved successfully.')
            else:
                flash('Both title and content are required.')
            return redirect(url_for('reddit_ai_agent'))
        elif action == 'edit':
            reply_id = request.form.get('reply_id')
            title = request.form.get('title')
            content = request.form.get('content')
            reply = db.session.get(SavedReply, int(reply_id)) if reply_id else None
            if reply and reply.user_id == user_id:
                reply.title = title
                reply.content = content
                db.session.commit()
                flash('Reply updated.')
            else:
                flash('Edit failed.')
            return redirect(url_for('reddit_ai_agent'))
        elif action == 'delete':
            reply_id = request.form.get('reply_id')
            reply = db.session.get(SavedReply, int(reply_id)) if reply_id else None
            if reply and reply.user_id == user_id:
                db.session.delete(reply)
                db.session.commit()
                flash('Reply deleted.')
            else:
                flash('Delete failed.')
            return redirect(url_for('reddit_ai_agent'))
    replies = SavedReply.query.filter_by(user_id=user_id).order_by(SavedReply.id.desc()).all()
    return render_template('reddit_ai_agent.html', replies=replies, user=user)

@app.route('/generate_reply', methods=['POST'])
@login_required
def generate_reply():
    data = request.get_json()
    topic = data.get('topic')
    if not topic:
        return jsonify({'error': 'Missing topic'}), 400
    prompt = (
        f"You are a helpful community manager. Write a concise, friendly, and authentic-sounding Reddit comment about the topic: '{topic}'. "
        "The comment should be helpful and not sound like a corporate advertisement. Do not include a greeting or a sign-off."
    )
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        generated_text = response.text.strip()
        return jsonify({'reply_content': generated_text})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/content_studio')
@login_required
def content_studio():
    user_id = session['user_id']
    keywords = Keyword.query.filter_by(user_id=user_id).all()
    return render_template('content_studio.html', keywords=keywords)

@app.route('/generate_content_brief/<int:keyword_id>')
@login_required
def generate_content_brief(keyword_id):
    user_id = session['user_id']
    keyword = db.session.get(Keyword, keyword_id)
    if not keyword or keyword.user_id != user_id:
        flash('Keyword not found or unauthorized.')
        return redirect(url_for('content_studio'))
    found_posts = FoundPost.query.filter_by(user_id=user_id).filter(FoundPost.text.ilike(f'%{keyword.text}%')).limit(20).all()
    prompt = ""
    if found_posts:
        all_comments = '\n'.join([f"- {post.text}" for post in found_posts])
        prompt = (
            f"You are an expert Content Strategist. Based on the following Reddit user comments about '{keyword.text}', generate a JSON object with the following keys: "
            f"'title' (a compelling blog post title), 'hook' (an attention-grabbing opening paragraph), "
            f"'talking_points' (a list of 3-5 key points to cover, as strings), and 'call_to_action' (a single actionable suggestion for the reader). "
            f"Return ONLY a valid JSON object, no extra text or formatting.\n\nUser Comments:\n{all_comments}"
        )
    else:
        prompt = (
            f"You are an expert Content Strategist. Based only on the keyword '{keyword.text}', generate a JSON object with the following keys: "
            f"'title' (a compelling blog post title), 'hook' (an attention-grabbing opening paragraph), "
            f"'talking_points' (a list of 3-5 key points to cover, as strings), and 'call_to_action' (a single actionable suggestion for the reader). "
            f"Return ONLY a valid JSON object, no extra text or formatting."
        )
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        cleaned_response_text = response.text.strip().replace('`', '').replace('json', '')
        brief_data = json.loads(cleaned_response_text)
    except Exception as e:
        traceback.print_exc()
        flash('Error generating content brief: Could not connect to AI service.')
        return redirect(url_for('content_studio'))
    return render_template('content_brief.html', brief=brief_data, keyword_text=keyword.text)

@app.route('/reddit/share-of-voice')
@login_required
def reddit_share_of_voice():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    mentions_query = (
        db.session.query(func.strftime('%Y-%m-%d', FoundPost.created_at).label('date'), func.count(FoundPost.id))
        .filter(FoundPost.user_id == user_id)
        .group_by('date')
        .order_by('date')
        .all()
    )
    mentions_over_time = {
        'labels': [row[0] for row in mentions_query],
        'data': [row[1] for row in mentions_query]
    }
    top_subreddits_query = (
        db.session.query(FoundPost.subreddit, func.count(FoundPost.id).label('mention_count'))
        .filter(FoundPost.user_id == user_id)
        .group_by(FoundPost.subreddit)
        .order_by(func.count(FoundPost.id).desc())
        .limit(5)
        .all()
    )
    top_subreddits = {
        'labels': [row[0] for row in top_subreddits_query],
        'data': [row[1] for row in top_subreddits_query]
    }
    top_authors_query = (
        db.session.query(FoundPost.author, func.count(FoundPost.id).label('mention_count'))
        .filter(FoundPost.user_id == user_id)
        .group_by(FoundPost.author)
        .order_by(func.count(FoundPost.id).desc())
        .limit(5)
        .all()
    )
    top_authors = {
        'labels': [row[0] for row in top_authors_query],
        'data': [row[1] for row in top_authors_query]
    }
    return render_template('reddit_share_of_voice.html', user=user, mentions_over_time=mentions_over_time, top_subreddits=top_subreddits, top_authors=top_authors)

@app.route('/analyze_website', methods=['POST'])
def analyze_website():
    try:
        website_url = request.json['website_url']
        headers = {'User-Agent': 'Mozilla/5.0'}
        page = requests.get(website_url, headers=headers, timeout=10)
        soup = BeautifulSoup(page.content, 'html.parser')
        scraped_text = ' '.join(soup.get_text().split())[:15000]
        prompt_text = (
            "Based on the following website text, act as a business analyst and return ONLY a valid JSON object "
            "with the following structure: {\"business_name\": \"...\", \"business_profile\": {\"core_offering\": \"...\", "
            "\"target_customer\": \"...\"}, \"suggested_keywords\": [\"...\"], \"suggested_subreddits\": [\"...\"]}. "
            "Do not include any other text, formatting, or markdown backticks. Website Text: "
            f"{scraped_text}"
        )
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt_text)
        print("Gemini raw response:", response.text)
        cleaned_response_text = response.text.strip().replace('`', '').replace('json', '')
        try:
            ai_data = json.loads(cleaned_response_text)
        except Exception as json_err:
            print("JSON decode error:", json_err)
            return jsonify({"error": "AI response was not valid JSON. See server logs for details."}), 500
        return jsonify(ai_data)
    except Exception as e:
        print("Analysis error:", e)
        traceback.print_exc()
        return jsonify({"error": "An error occurred during analysis. See server logs for details."}), 500

# Placeholder routes for new sidebar pages
@app.route('/reddit/keywords')
@login_required
def reddit_keywords():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    return render_template('coming_soon.html', user=user)

@app.route('/blogs')
@login_required
def blogs():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    return render_template('coming_soon.html', user=user)

@app.route('/chatgpt')
@login_required
def chatgpt():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    return render_template('coming_soon.html', user=user)

@app.route('/knowledgebase')
@login_required
def knowledgebase():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    return render_template('coming_soon.html', user=user)


# =============================
# Main Execution Block
# =============================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)