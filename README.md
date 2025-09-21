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

This lab contains **8 intentional vulnerabilities** designed to teach specific security concepts. Each vulnerability is carefully crafted to demonstrate real-world attack scenarios.

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

- [ ] **Challenge 1**: Successfully performed SQL injection attack
- [ ] **Challenge 2**: Discovered plaintext password storage
- [ ] **Challenge 3**: Executed XSS attack in post content
- [ ] **Challenge 4**: Uploaded malicious file successfully
- [ ] **Challenge 5**: Bypassed authorization to access other users' posts
- [ ] **Challenge 6**: Analyzed session management vulnerabilities
- [ ] **Challenge 7**: Found information disclosure issues
- [ ] **Challenge 8**: Identified missing security headers

## 🎓 Learning Outcomes

After completing this lab, you will have:

✅ **Hands-on Experience** with 8 major web application vulnerabilities
✅ **Practical Skills** in penetration testing techniques
✅ **Deep Understanding** of how vulnerabilities are exploited
✅ **Real-world Knowledge** applicable to bug bounty hunting and security testing
✅ **Defensive Awareness** of what to look for in secure applications

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

## 🔧 Lab Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, Jinja2 templating
- **File Handling**: Werkzeug secure_filename
- **Session Management**: Flask sessions
- **Vulnerabilities**: Intentionally implemented for learning

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

- **Beginner** (⭐⭐): Challenges 2, 7, 8 - Basic security concepts
- **Intermediate** (⭐⭐⭐): Challenges 1, 3, 6 - Common attack techniques  
- **Advanced** (⭐⭐⭐⭐): Challenges 4, 5 - Complex exploitation methods

## 🏅 Lab Achievements

Complete challenges to earn achievements:

- 🥉 **Security Novice**: Complete 3 challenges
- 🥈 **Penetration Tester**: Complete 6 challenges  
- 🥇 **Security Expert**: Complete all 8 challenges
- 🏆 **Lab Master**: Complete all challenges and document your findings

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

## 🚀 Ready to Start?

**Begin your cybersecurity learning journey!** 

1. Set up the lab environment
2. Start with Challenge 1 (SQL Injection)
3. Work through each challenge systematically
4. Document your findings and techniques
5. Apply your knowledge to real-world scenarios

**Remember**: This lab is intentionally vulnerable for educational purposes. Use it responsibly and only in controlled, educational environments!

---

*Happy Learning! 🛡️🔒*