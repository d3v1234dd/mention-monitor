import os
import time
import praw
import re
from dotenv import load_dotenv

# Load environment variables at the very beginning
load_dotenv()

# Now, import from our app and configure libraries
from app import app, db, User, Keyword, FoundPost, send_email_alert
import google.generativeai as genai

# Configure Google AI
try:
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
except Exception as e:
    print(f"FATAL: Could not configure Google AI. Check GOOGLE_API_KEY. Error: {e}")
    exit()

# Configure Reddit API
try:
    reddit = praw.Reddit(
        client_id=os.getenv("REDDIT_CLIENT_ID"),
        client_secret=os.getenv("REDDIT_CLIENT_SECRET"),
        user_agent=os.getenv("REDDIT_USER_AGENT")
    )
    print("Successfully connected to Reddit API.")
except Exception as e:
    print(f"FATAL: Could not connect to Reddit API. Check Reddit credentials. Error: {e}")
    exit()

def main():
    """Main function to run the Reddit monitor."""
    print("Monitoring Reddit comments for all user keywords...")

    with app.app_context():
        while True:
            try:
                all_keywords = list(set([k.text.lower() for k in Keyword.query.all()]))
                
                if not all_keywords:
                    print("No keywords in database. Waiting 30 seconds...")
                    time.sleep(30)
                    continue

                for comment in reddit.subreddit("all").stream.comments(skip_existing=True):
                    comment_body = comment.body.lower()
                    
                    matched_keywords = []
                    for kw in all_keywords:
                        pattern = r'\b{}\b'.format(re.escape(kw))
                        if re.search(pattern, comment_body, re.IGNORECASE):
                            matched_keywords.append(kw)
                    
                    if matched_keywords:
                        author = comment.author.name if comment.author else "[deleted]"
                        subreddit = comment.subreddit.display_name
                        permalink = f"https://www.reddit.com{comment.permalink}"
                        
                        for matched_kw in set(matched_keywords):
                            # --- AI Intent Analysis ---
                            intent_tag = "General Discussion" # Default value
                            try:
                                intent_prompt = f"Classify the following Reddit comment into one of these categories: 'Buying Question', 'Support Request', 'Competitor Complaint', or 'General Discussion'. Respond with the category name only. Comment: '{comment.body}'"
                                # ** THIS IS THE FIX for the Gemini Error **
                                intent_model = genai.GenerativeModel('gemini-2.5-flash') 
                                intent_response = intent_model.generate_content(intent_prompt)
                                intent_tag = intent_response.text.strip()
                            except Exception as e:
                                print(f"Could not get AI intent analysis: {e}")

                            # --- Find Users and Notify ---
                            keyword_objs = Keyword.query.filter(db.func.lower(Keyword.text) == matched_kw).all()
                            user_ids = set([k.user_id for k in keyword_objs])
                            users_to_notify = User.query.filter(User.id.in_(user_ids)).all()
                            
                            for user in users_to_notify:
                                subject = f"New Reddit Mention for '{matched_kw}'"
                                body = (
                                    f"<h3>New Mention Found</h3>"
                                    f"<p><b>Keyword:</b> {matched_kw}</p>"
                                    f"<p><b>Intent:</b> {intent_tag}</p>"
                                    f"<p><b>Author:</b> u/{author}</p>"
                                    f"<p><b>Subreddit:</b> r/{subreddit}</p>"
                                    f"<p><b>Comment:</b></p><blockquote>{comment.body}</blockquote>"
                                    f"<p><a href='{permalink}'>Click here to view on Reddit</a></p>"
                                )
                                print(f"Match for '{matched_kw}' | Intent: {intent_tag} | Notifying: {user.email}")
                                
                                # Save to DB
                                new_post = FoundPost(text=comment.body, author=author, subreddit=subreddit, permalink=permalink, user_id=user.id, intent=intent_tag)
                                db.session.add(new_post)
                                
                                # Send Email
                                send_email_alert(subject, user.email, body)
                            
                            db.session.commit()

            except KeyboardInterrupt:
                print("\nStopping monitor.")
                break
            except Exception as e:
                print(f"A major error occurred: {e}. Retrying in 15 seconds...")
                db.session.rollback()
                time.sleep(15)

if __name__ == "__main__":
    main()