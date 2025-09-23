# 🛡️ Vulnerable Web App Labs

**An intentionally vulnerable Flask web application designed for hands-on cybersecurity learning and penetration testing practice.**

Welcome to our comprehensive vulnerable lab environment! This project is specifically crafted to teach core cybersecurity concepts through practical, hands-on experience. Similar to TryHackMe and PortSwigger labs, this application contains **intentional vulnerabilities** that allow you to learn, practice, and master essential security testing techniques in a safe, controlled environment.

## 🎯 Learning Objectives

This lab is designed to teach you:

- **SQL Injection** - Understanding and exploiting database vulnerabilities
- **Authentication Bypass** - Weak password handling and session management
- **File Upload Vulnerabilities** - Malicious file upload exploitation
- **Cross-Site Scripting (XSS)** - Client-side code injection attacks
- **Insecure Direct Object References (IDOR)** - Authorization bypass techniques
- **Information Disclosure** - Sensitive data exposure vulnerabilities
- **Session Management Flaws** - Session hijacking and fixation
- **Input Validation Issues** - Data sanitization and validation bypass

## 🎓 Who This Lab Is For

- **Cybersecurity Students** - Learning web application security fundamentals
- **Penetration Testers** - Practicing real-world attack techniques
- **Bug Bounty Hunters** - Developing vulnerability discovery skills
- **Security Professionals** - Teaching and demonstrating vulnerabilities
- **Developers** - Understanding security pitfalls in web development
- **IT Professionals** - Building security awareness and knowledge

## ⚠️ **IMPORTANT SECURITY WARNING**

**This application contains intentional security vulnerabilities and should NEVER be deployed in a production environment or exposed to the internet.** It is designed exclusively for educational purposes in controlled, isolated environments.

## 🚀 Features

### Core Functionality
- **User Authentication System** (with vulnerabilities)
- **Social Media-like Interface** with posts and images
- **File Upload System** for images
- **User Profile Management**
- **Post Creation, Editing, and Deletion**
- **Public Feed and Personal Gallery**
- **Responsive Web Design**

### Pages and Routes
- `/` - Home page (redirects to dashboard or login)
- `/login` - User login
- `/signup` - User registration
- `/dashboard` - User dashboard
- `/profile` - User profile management
- `/change-password` - Password change functionality
- `/create-post` - Create new posts with images
- `/feed` - Public feed showing all posts
- `/gallery` - Personal gallery of user's posts
- `/edit-post/<id>` - Edit existing posts
- `/delete-post/<id>` - Delete posts

## 🎯 Lab Challenges & Vulnerabilities

This lab contains **14 intentional vulnerabilities** designed to teach specific security concepts. Each vulnerability is carefully crafted to demonstrate real-world attack scenarios and is categorized by difficulty level.

### Challenge 1: SQL Injection Attack
- **Vulnerability Type**: SQL Injection
- **Difficulty**: ⭐⭐⭐
- **Learning Goal**: Understand how unsanitized user input can lead to database compromise
- **Attack Vector**: Login form username field
- **Hint**: Try classic SQL injection payloads like `' OR '1'='1`

### Challenge 2: Authentication Bypass
- **Vulnerability Type**: No Password Hashing
- **Difficulty**: ⭐⭐
- **Learning Goal**: Learn why password hashing is critical
- **Attack Vector**: Direct database access reveals plaintext passwords
- **Hint**: Check the database file directly

### Challenge 3: Session Hijacking
- **Vulnerability Type**: Insecure Session Management
- **Difficulty**: ⭐⭐⭐
- **Learning Goal**: Understand session security and token management
- **Attack Vector**: Predictable session tokens and hardcoded secrets
- **Hint**: Examine session cookies and secret key

### Challenge 4: Malicious File Upload
- **Vulnerability Type**: File Upload Vulnerabilities
- **Difficulty**: ⭐⭐⭐⭐
- **Learning Goal**: Learn file upload security best practices
- **Attack Vector**: Upload malicious files to gain server access
- **Hint**: Try uploading files with different extensions and content

### Challenge 5: Cross-Site Scripting (XSS)
- **Vulnerability Type**: XSS
- **Difficulty**: ⭐⭐⭐
- **Learning Goal**: Understand client-side code injection
- **Attack Vector**: Post content and user input fields
- **Hint**: Try injecting JavaScript code in post content

### Challenge 6: Authorization Bypass (IDOR)
- **Vulnerability Type**: Insecure Direct Object References
- **Difficulty**: ⭐⭐⭐⭐
- **Learning Goal**: Learn about proper authorization checks
- **Attack Vector**: Manipulate post IDs to access other users' content
- **Hint**: Try changing post IDs in URLs

### Challenge 7: Information Disclosure
- **Vulnerability Type**: Information Disclosure
- **Difficulty**: ⭐⭐
- **Learning Goal**: Understand what information should not be exposed
- **Attack Vector**: Error messages and debug information
- **Hint**: Look for detailed error messages and debug output

### Challenge 8: Missing Security Headers
- **Vulnerability Type**: Security Headers
- **Difficulty**: ⭐⭐
- **Learning Goal**: Learn about HTTP security headers
- **Attack Vector**: Various client-side attacks due to missing headers
- **Hint**: Check response headers for security controls

### Challenge 9: CSRF (Cross-Site Request Forgery)
- **Vulnerability Type**: CSRF
- **Difficulty**: ⭐⭐⭐
- **Learning Goal**: Understand how attackers can perform actions on behalf of users
- **Attack Vector**: Forms without CSRF token validation
- **Hint**: Try creating malicious HTML forms that submit to the application

### Challenge 10: Brute Force Attack
- **Vulnerability Type**: Brute Force
- **Difficulty**: ⭐⭐
- **Learning Goal**: Learn about password attacks and rate limiting importance
- **Attack Vector**: Login attempts without rate limiting
- **Hint**: Try multiple username/password combinations rapidly

### Challenge 11: Clickjacking Attack
- **Vulnerability Type**: Clickjacking
- **Difficulty**: ⭐⭐
- **Learning Goal**: Understand how attackers trick users into clicking hidden elements
- **Attack Vector**: Iframe overlays and missing X-Frame-Options header
- **Hint**: Look for ways to embed the application in iframes

### Challenge 12: SSRF (Server-Side Request Forgery)
- **Vulnerability Type**: SSRF
- **Difficulty**: ⭐⭐⭐⭐
- **Learning Goal**: Learn how attackers can make servers request internal resources
- **Attack Vector**: URL fetching without validation
- **Hint**: Try internal URLs like http://localhost:22 or cloud metadata endpoints

### Challenge 13: XXE (XML External Entity)
- **Vulnerability Type**: XXE
- **Difficulty**: ⭐⭐⭐⭐
- **Learning Goal**: Understand XML parsing vulnerabilities and file reading
- **Attack Vector**: XML processing without external entity validation
- **Hint**: Try XML payloads with external entity declarations

### Challenge 14: Insecure Deserialization
- **Vulnerability Type**: Deserialization
- **Difficulty**: ⭐⭐⭐⭐⭐
- **Learning Goal**: Learn about code execution through deserialization
- **Attack Vector**: Pickle deserialization without validation
- **Hint**: Try base64-encoded serialized objects with malicious payloads

### Challenge 15: Race Condition
- **Vulnerability Type**: Race Condition
- **Difficulty**: ⭐⭐⭐
- **Learning Goal**: Understand timing-based vulnerabilities in concurrent systems
- **Attack Vector**: Concurrent database access without proper locking
- **Hint**: Try multiple rapid requests to see timing-based issues

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/ARSN72/Vulnerable-WebApp-Labs.git
   cd Vulnerable-WebApp-Labs
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database**
   ```bash
   python migrate.py
   ```

4. **Run the application**
   ```bash
   python flask_vulnerable_app.py
   ```

5. **Access the application**
   - Open your browser and navigate to `http://localhost:5000`
   - The application will be running in debug mode

## 🚀 Lab Setup & Getting Started

### Step 1: Environment Setup
1. **Clone and Install**
   ```bash
   git clone https://github.com/ARSN72/Vulnerable-WebApp-Labs.git
   cd Vulnerable-WebApp-Labs
   pip install -r requirements.txt
   ```

2. **Initialize the Lab**
   ```bash
   python migrate.py
   python flask_vulnerable_app.py
   ```

3. **Access the Lab**
   - Open browser to `http://localhost:5000`
   - You're now ready to start the challenges!

### Step 2: Basic Lab Navigation

1. **Create Test Accounts**
   - Navigate to `/signup`
   - Create multiple test accounts with different usernames
   - **Learning Note**: Observe how passwords are stored (hint: check the database!)

2. **Explore the Interface**
   - Login and explore the dashboard
   - Create some test posts with images
   - Familiarize yourself with all the features

## 🎯 Lab Challenges Walkthrough

### Challenge 1: SQL Injection Mastery
**Objective**: Bypass authentication using SQL injection

**Steps**:
1. Go to the login page
2. In the username field, try: `admin' OR '1'='1' --`
3. Leave password empty or enter anything
4. **Expected Result**: You should be logged in as the first user in the database

**Learning Points**:
- How unsanitized input leads to SQL injection
- Understanding SQL query structure
- Classic authentication bypass techniques

### Challenge 2: Password Security Analysis
**Objective**: Discover how passwords are stored

**Steps**:
1. Create a test account with password "test123"
2. Open the `database.db` file with any SQLite browser
3. Examine the users table
4. **Expected Result**: You'll see passwords stored in plain text

**Learning Points**:
- Importance of password hashing
- Database security considerations
- Real-world impact of poor password storage

### Challenge 3: XSS Attack Simulation
**Objective**: Execute client-side code injection

**Steps**:
1. Create a new post
2. In the post content, enter: `<script>alert('XSS Vulnerability Found!')</script>`
3. Submit the post
4. View the post in the feed
5. **Expected Result**: JavaScript alert should execute

**Learning Points**:
- How XSS attacks work
- Input validation importance
- Client-side security risks

### Challenge 4: File Upload Exploitation
**Objective**: Upload malicious files

**Steps**:
1. Create a text file with content: `<?php echo "File Upload Vulnerability!"; ?>`
2. Save it as `test.php`
3. Try to upload it through the create post feature
4. **Expected Result**: File should be uploaded despite being a PHP file

**Learning Points**:
- File upload security risks
- File type validation bypass
- Server-side execution risks

### Challenge 5: IDOR (Insecure Direct Object Reference)
**Objective**: Access other users' posts

**Steps**:
1. Create a post and note its ID from the URL
2. Logout and create another account
3. Try to access the edit URL of the first user's post: `/edit-post/1`
4. **Expected Result**: You should be able to edit another user's post

**Learning Points**:
- Authorization bypass techniques
- Object reference security
- Access control importance

### Challenge 6: Session Security Analysis
**Objective**: Analyze session management flaws

**Steps**:
1. Login and examine browser cookies
2. Look for session cookie values
3. Try to predict or manipulate session values
4. **Expected Result**: Session tokens may be predictable

**Learning Points**:
- Session security fundamentals
- Token generation and validation
- Session hijacking techniques

### Challenge 7: Information Disclosure Discovery
**Objective**: Find sensitive information exposure

**Steps**:
1. Try to access non-existent pages (e.g., `/nonexistent`)
2. Look for detailed error messages
3. Check if debug mode is enabled
4. **Expected Result**: Detailed error information should be visible

**Learning Points**:
- Information disclosure risks
- Error handling security
- Debug mode dangers

### Challenge 8: Security Headers Analysis
**Objective**: Identify missing security headers

**Steps**:
1. Use browser developer tools or curl to examine HTTP headers
2. Look for security headers like CSP, HSTS, X-Frame-Options
3. **Expected Result**: Most security headers should be missing

**Learning Points**:
- HTTP security headers importance
- Client-side attack prevention
- Security header implementation

## 🏗️ Project Structure

```
Vulnerable-WebApp-Labs/
├── flask_vulnerable_app.py    # Main Flask application
├── migrate.py                 # Database migration script
├── requirements.txt           # Python dependencies
├── database.db               # SQLite database file
├── static/
│   ├── style.css            # CSS styling
│   └── uploads/             # Uploaded files directory
└── templates/               # HTML templates
    ├── base.html           # Base template
    ├── login.html          # Login page
    ├── signup.html         # Registration page
    ├── dashboard.html      # User dashboard
    ├── profile.html        # User profile
    ├── create_post.html    # Post creation
    ├── feed.html           # Public feed
    ├── gallery.html        # User gallery
    ├── edit_post.html      # Post editing
    └── change_password.html # Password change
```

## 🏆 Lab Completion Checklist

Track your progress through each challenge:

### Core Vulnerabilities (Original 8)
- [ ] **Challenge 1**: Successfully performed SQL injection attack
- [ ] **Challenge 2**: Discovered plaintext password storage
- [ ] **Challenge 3**: Executed XSS attack in post content
- [ ] **Challenge 4**: Uploaded malicious file successfully
- [ ] **Challenge 5**: Bypassed authorization to access other users' posts
- [ ] **Challenge 6**: Analyzed session management vulnerabilities
- [ ] **Challenge 7**: Found information disclosure issues
- [ ] **Challenge 8**: Identified missing security headers

### Advanced Vulnerabilities (New 7)
- [ ] **Challenge 9**: Performed CSRF attack successfully
- [ ] **Challenge 10**: Executed brute force attack
- [ ] **Challenge 11**: Demonstrated clickjacking vulnerability
- [ ] **Challenge 12**: Exploited SSRF to access internal resources
- [ ] **Challenge 13**: Used XXE to read files or make requests
- [ ] **Challenge 14**: Executed code through insecure deserialization
- [ ] **Challenge 15**: Exploited race condition vulnerability

## 🎓 Learning Outcomes

After completing this lab, you will have:

✅ **Hands-on Experience** with 15 major web application vulnerabilities
✅ **Practical Skills** in penetration testing techniques
✅ **Deep Understanding** of how vulnerabilities are exploited
✅ **Real-world Knowledge** applicable to bug bounty hunting and security testing
✅ **Defensive Awareness** of what to look for in secure applications
✅ **Advanced Skills** in modern attack vectors (SSRF, XXE, Deserialization)
✅ **Gamification Experience** with points, achievements, and progress tracking

## 🛡️ Security Best Practices (What NOT to do)

This lab demonstrates what **NOT** to do in production:

- ❌ Never store passwords in plain text
- ❌ Never use hardcoded secret keys
- ❌ Never trust user input without validation
- ❌ Never enable debug mode in production
- ❌ Never skip input sanitization
- ❌ Never ignore file upload security
- ❌ Never use weak session management
- ❌ Never expose sensitive error information

## 🔧 Technology Stack & Development Details

### Core Technologies
- **Backend Framework**: Python Flask 2.3.3
- **Database**: SQLite3 (file-based database)
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Templating Engine**: Jinja2 (Flask's built-in templating)
- **Web Server**: Werkzeug (Flask's WSGI toolkit)
- **Session Management**: Flask-Session (server-side sessions)

### Python Libraries & Dependencies
```python
# Core Framework
Flask==2.3.3              # Web application framework
Werkzeug==2.3.7           # WSGI toolkit and utilities
gunicorn==21.2.0          # Production WSGI server

# HTTP & Network
requests==2.31.0          # HTTP library for SSRF functionality

# Built-in Python Modules Used
sqlite3                   # Database operations
os                       # File system operations
re                       # Regular expressions
time                     # Timing functions
random                   # Random number generation
base64                   # Base64 encoding/decoding
pickle                   # Object serialization
xml.etree.ElementTree    # XML parsing
```

### Database Schema
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT
);

-- Posts table
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    image TEXT,
    timestamp TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- User statistics table (for gamification)
CREATE TABLE user_stats (
    user_id INTEGER PRIMARY KEY,
    total_points INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    achievements_earned INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    balance INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- User progress tracking
CREATE TABLE user_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    vulnerability_type TEXT NOT NULL,
    points INTEGER NOT NULL,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Achievements system
CREATE TABLE achievements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    achievement_name TEXT NOT NULL,
    achievement_description TEXT NOT NULL,
    points INTEGER NOT NULL,
    earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Frontend Technologies
- **HTML5**: Semantic markup, form validation
- **CSS3**: 
  - Flexbox and Grid layouts
  - CSS Variables for theming
  - Glass morphism design effects
  - Responsive design with media queries
  - CSS animations and transitions
  - Custom properties and gradients
- **JavaScript**: 
  - Vanilla JavaScript (no frameworks)
  - DOM manipulation
  - Event handling
  - AJAX requests (where applicable)

### Security Vulnerabilities Implemented
1. **SQL Injection** - Direct string concatenation in queries
2. **Cross-Site Scripting (XSS)** - Unsanitized user input rendering
3. **File Upload Vulnerabilities** - Insufficient file type validation
4. **Insecure Direct Object References (IDOR)** - Missing authorization checks
5. **Information Disclosure** - Detailed error messages and debug info
6. **Session Management Flaws** - Predictable session tokens
7. **CSRF (Cross-Site Request Forgery)** - Missing CSRF tokens
8. **Brute Force Vulnerabilities** - No rate limiting
9. **Clickjacking** - Missing X-Frame-Options header
10. **SSRF (Server-Side Request Forgery)** - Unvalidated URL requests
11. **XXE (XML External Entity)** - Unsafe XML parsing
12. **Insecure Deserialization** - Pickle deserialization without validation
13. **Race Conditions** - Concurrent database access without locking

### Development Architecture
```
Vulnerable-WebApp-Labs/
├── flask_vulnerable_app.py          # Main Flask application (583 lines)
├── migrate.py                       # Database migration script
├── requirements.txt                 # Python dependencies
├── database.db                      # SQLite database file
├── static/
│   ├── style.css                   # Comprehensive CSS (1336 lines)
│   └── uploads/                     # User uploaded files directory
└── templates/                       # Jinja2 HTML templates
    ├── base.html                   # Base template with navigation
    ├── login.html                  # Authentication page
    ├── signup.html                 # User registration
    ├── dashboard.html              # Main dashboard with challenges
    ├── profile.html                # User profile management
    ├── create_post.html            # Post creation form
    ├── feed.html                   # Public posts feed
    ├── gallery.html                # User's personal gallery
    ├── edit_post.html              # Post editing interface
    ├── change_password.html        # Password change form
    ├── scoreboard.html             # Leaderboard and progress
    ├── csrf_demo.html              # CSRF vulnerability demo
    ├── brute_force_demo.html       # Brute force attack demo
    ├── clickjacking_demo.html      # Clickjacking demo
    ├── ssrf_demo.html              # SSRF vulnerability demo
    ├── xxe_demo.html               # XXE vulnerability demo
    ├── deserialization_demo.html   # Deserialization demo
    └── race_condition_demo.html    # Race condition demo
```

### Gamification System
- **Points System**: Users earn points for finding vulnerabilities
- **Achievement System**: Unlock achievements for completing challenges
- **Level System**: Progress through levels based on total points
- **Leaderboard**: Global ranking of all users
- **Progress Tracking**: Detailed statistics and vulnerability history

### Key Features Implemented
- **Modern UI/UX**: Glass morphism design with responsive layout
- **Interactive Demos**: Hands-on vulnerability demonstrations
- **Educational Content**: Step-by-step guides and hints
- **Progress Tracking**: Comprehensive user statistics
- **Real-time Feedback**: Immediate success/error messages
- **Professional Design**: Industry-standard interface design

### Development Tools & Environment
- **IDE**: Compatible with VS Code, PyCharm, Sublime Text
- **Version Control**: Git
- **Database Management**: SQLite Browser, DB Browser for SQLite
- **Testing**: Flask's built-in development server
- **Debugging**: Flask's debug mode with Werkzeug debugger
- **Code Quality**: Python PEP 8 compliance

### Performance Considerations
- **Database**: SQLite for simplicity and portability
- **Caching**: Flask session-based caching
- **File Storage**: Local file system for uploaded files
- **Memory Usage**: Optimized for educational purposes
- **Concurrency**: Handles multiple users simultaneously

### Security Considerations (Intentional Vulnerabilities)
- **No Input Validation**: Demonstrates importance of input sanitization
- **No Output Encoding**: Shows XSS vulnerabilities
- **No Authentication**: Teaches authorization concepts
- **No Rate Limiting**: Demonstrates brute force attacks
- **No CSRF Protection**: Shows cross-site request forgery
- **No Security Headers**: Teaches HTTP security headers
- **Debug Mode Enabled**: Shows information disclosure risks

## 📚 Additional Learning Resources

### Recommended Next Steps:
1. **TryHackMe**: Practice more web application challenges
2. **PortSwigger Academy**: Advanced web security topics
3. **OWASP Top 10**: Study the official vulnerability list
4. **Burp Suite**: Learn professional penetration testing tools
5. **WebGoat**: Another vulnerable application for practice

### Tools to Use with This Lab:
- **Burp Suite**: For intercepting and modifying requests
- **OWASP ZAP**: Free alternative to Burp Suite
- **SQLMap**: Automated SQL injection testing
- **Browser Developer Tools**: For analyzing requests and responses

## 🎯 Lab Difficulty Levels

- **Beginner** (⭐⭐): Challenges 2, 7, 8, 10, 11 - Basic security concepts
- **Intermediate** (⭐⭐⭐): Challenges 1, 3, 6, 9, 15 - Common attack techniques  
- **Advanced** (⭐⭐⭐⭐): Challenges 4, 5, 12, 13 - Complex exploitation methods
- **Expert** (⭐⭐⭐⭐⭐): Challenge 14 - Advanced deserialization attacks

## 🏅 Lab Achievements

Complete challenges to earn achievements:

- 🥉 **Security Novice**: Complete 5 challenges
- 🥈 **Penetration Tester**: Complete 10 challenges  
- 🥇 **Security Expert**: Complete 12 challenges
- 💎 **Advanced Hacker**: Complete 14 challenges
- 🏆 **Lab Master**: Complete all 15 challenges and document your findings
- 🌟 **Vulnerability Hunter**: Find all vulnerability types
- 🎯 **Perfect Score**: Earn maximum points on all challenges

## 🤝 Contributing to the Lab

This is an educational project designed for cybersecurity learning. We welcome contributions that:

- Add new realistic vulnerabilities for learning
- Improve the lab experience and documentation
- Create additional challenge scenarios
- Enhance the educational content

## ⚖️ Legal Disclaimer

**This lab is provided for educational purposes only.** 

- Use only in controlled, isolated environments
- Never deploy on production systems or expose to the internet
- Ensure you have proper authorization before testing
- The authors are not responsible for any misuse of this application

## 📞 Lab Support & Community

- **Documentation**: Refer to this README for detailed instructions
- **Learning Resources**: Check the additional resources section
- **Community**: Join cybersecurity learning communities for support
- **Instructor Help**: Consult with your cybersecurity instructor

---

## 🎮 Gamification Features

This lab includes a comprehensive gamification system to enhance learning:

### Points System
- **SQL Injection**: 100 points
- **XSS Attack**: 80 points  
- **File Upload**: 90 points
- **IDOR**: 85 points
- **CSRF**: 80 points
- **Brute Force**: 60 points
- **Clickjacking**: 70 points
- **SSRF**: 90 points
- **XXE**: 85 points
- **Deserialization**: 95 points
- **Race Condition**: 70 points

### Achievement System
- **First Login**: Welcome achievement
- **Vulnerability Hunter**: Find your first vulnerability
- **SQL Master**: Successfully perform SQL injection
- **XSS Expert**: Execute XSS attacks
- **File Upload Pro**: Upload malicious files
- **Authorization Bypass**: Exploit IDOR vulnerabilities
- **And many more!**

### Progress Tracking
- **Personal Dashboard**: View your progress and statistics
- **Global Scoreboard**: Compete with other learners
- **Level System**: Progress through levels based on points
- **Vulnerability History**: Track all your successful exploits

## 🚀 Ready to Start?

**Begin your cybersecurity learning journey!** 

1. Set up the lab environment
2. Start with Challenge 1 (SQL Injection)
3. Work through each challenge systematically
4. Track your progress and earn achievements
5. Compete on the global scoreboard
6. Document your findings and techniques
7. Apply your knowledge to real-world scenarios

**Remember**: This lab is intentionally vulnerable for educational purposes. Use it responsibly and only in controlled, educational environments!

---

*Happy Learning! 🛡️🔒🎮*