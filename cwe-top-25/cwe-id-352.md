# CWE 352

<mark style="color:red;">****</mark>[<mark style="color:red;">**Disclaimer**</mark>](../readme/disclaimer.md)<mark style="color:red;">****</mark>

## About CWE ID 434

<mark style="color:green;">**Cross-Site Request Forgery (CSRF)**</mark>

CWE ID 352 refers to "Cross-Site Request Forgery (CSRF)" vulnerability which could allow an attacker to execute unwanted actions on a web application on behalf of an authenticated user. The impact of this vulnerability could range from unauthorized actions to disclosure of sensitive information.

### Impact

* Allows an attacker to bypass authentication and access sensitive data.
* Can be used to execute arbitrary code and take control of a system.
* Can be used to modify, delete, or add data to a system, potentially causing data loss or corruption.
* Can be used to launch attacks against other systems or networks from the compromised system.
* Can result in reputational damage, financial losses, and legal repercussions for the affected organization.

## Example with Code explanation

### JAVA

### _This is an example of the vulnerable code._

```java
// CSRF vulnerable Java code
@WebServlet("/transfer")
public class TransferServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Get parameters from request
        String fromAccount = request.getParameter("fromAccount");
        String toAccount = request.getParameter("toAccount");
        double amount = Double.parseDouble(request.getParameter("amount"));

        // Transfer money
        Bank.transfer(fromAccount, toAccount, amount);

        response.sendRedirect("/success");
    }
}
```

This code is vulnerable to CSRF because there is no mechanism to ensure that the request is coming from a legitimate source. An attacker can create a forged request, tricking the user into performing unwanted actions without their knowledge. This can be done by crafting a specially designed link or by submitting a form on a malicious website.

This can be mitigated by

* To mitigate this vulnerability, the server should include a unique token with each form or link, and validate that the token is correct when the request is submitted. This technique is called CSRF token or anti-CSRF token. The token should be unpredictable, unique, and tied to the user session to prevent replay attacks.

### _Here is an example of Mitigated code_

```java
@WebServlet("/transfer")
public class TransferServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Get parameters from request
        String fromAccount = request.getParameter("fromAccount");
        String toAccount = request.getParameter("toAccount");
        double amount = Double.parseDouble(request.getParameter("amount"));

        // Verify CSRF token
        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        if (csrfToken == null || !csrfToken.equals(session.getAttribute("csrfToken"))) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "CSRF token missing or invalid");
            return;
        }

        // Transfer money
        Bank.transfer(fromAccount, toAccount, amount);

        response.sendRedirect("/success");
    }
}
```

This code is mitigated against the following vulnerabilities:

1. The server generates a unique CSRF token and includes it as a hidden field in the form that submits the transfer request.
2. When the request is processed, the server checks that the token included in the request matches the one that was generated and stored in the user's session.
3. If the tokens don't match, the request is rejected. This prevents an attacker from crafting a request that includes a valid transfer request but with an invalid or missing CSRF token.

### Python

### _This is an example of the vulnerable code._

```python
# CSRF vulnerable Python code
@app.route('/transfer', methods=['POST'])
def transfer():
    # Get parameters from request
    from_account = request.form['from_account']
    to_account = request.form['to_account']
    amount = float(request.form['amount'])

    # Transfer money
    bank.transfer(from_account, to_account, amount)

    return redirect('/success')
```

This code is vulnerable to CSRF attack because it does not include any CSRF protection mechanism, such as the use of CSRF tokens or same-site cookies.

An attacker could craft a malicious website that sends a POST request to the "/transfer" endpoint, causing the user's browser to automatically submit the request with the user's existing session cookies, thereby making the request appear legitimate to the server.

The attacker could then transfer money from the user's account without their knowledge or consent.

This can be mitigated by

* Store the token in the user session
* Server need to verify the token respective of the user’s session
* Drop the request if the token is missing or invalid

### _Here is an example of Mitigated code_

```python
# Mitigated Python code with CSRF token validation
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/transfer', methods=['POST'])
def transfer():
    # Get parameters from request
    from_account = request.form['from_account']
    to_account = request.form['to_account']
    amount = float(request.form['amount'])

    # Verify CSRF token
    csrf_token = request.form.get('csrf_token')
    if csrf_token is None or csrf_token != session.get('csrf_token'):
        return 'CSRF token missing or invalid', 400

    # Transfer money
    bank.transfer(from_account, to_account, amount)

    return redirect('/success')

# Generate and store a new CSRF token for each user session
@app.before_request
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(16).hex()
```

This code is mitigated against CWE-352

* In the mitigated code, a CSRF token is generated and stored in the user session. When the transfer request is made, the server verifies the token to ensure that the request is legitimate and not a CSRF attack. If the token is missing or invalid, an error response is sent.

### .NET

### _This is an example of the vulnerable code._

```vbnet
// CSRF vulnerable .NET code
[HttpPost]
public ActionResult Transfer(string fromAccount, string toAccount, double amount)
{
    // Transfer money
    Bank.Transfer(fromAccount, toAccount, amount);

    return RedirectToAction("Success");
}
```

This code is vulnerable to CSRF attacks as it does not include any mechanism to prevent unauthorized requests.

### _Here is an example of Mitigated code_

```vbnet
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult Transfer(string fromAccount, string toAccount, double amount)
{
    // Transfer money
    Bank.Transfer(fromAccount, toAccount, amount);

    return RedirectToAction("Success");
}
```

The **`ValidateAntiForgeryToken`** attribute ensures that the token in the hidden input field matches the token stored in the server-side session state. If the tokens do not match, the action method will not be executed. This mechanism helps prevent CSRF attacks by ensuring that only authorized requests are processed.

### Nodejs

### _This is an example of the vulnerable code._

```jsx
// CSRF vulnerable Node.js code
app.post('/transfer', (req, res) => {
  // Get parameters from request
  const fromAccount = req.body.fromAccount;
  const toAccount = req.body.toAccount;
  const amount = parseFloat(req.body.amount);

  // Transfer money
  bank.transfer(fromAccount, toAccount, amount);

  res.redirect('/success');
});
```

* The code appears to be vulnerable to CSRF because it does not include any mechanism to verify the origin of the request.
* An attacker could create a malicious form on their own website that would submit a transfer request to the victim's account on the bank's website, resulting in unauthorized transfer of funds.

### _Here is an example of Mitigated code_

```jsx
app.post('/transfer', (req, res) => {
  // Get parameters from request
  const fromAccount = req.body.fromAccount;
  const toAccount = req.body.toAccount;
  const amount = parseFloat(req.body.amount);
  
  // Verify CSRF token
  const csrfToken = req.body.csrfToken;
  if (!req.session.csrfToken || csrfToken !== req.session.csrfToken) {
    res.status(403).send('CSRF token missing or invalid');
    return;
  }
  
  // Transfer money
  bank.transfer(fromAccount, toAccount, amount);

  res.redirect('/success');
});
```

* This modified code, a CSRF token is generated when the user first visits the site and is stored in the session.
* The token is included in the transfer request, and the server verifies that the token in the request matches the one stored in the session before allowing the transfer to proceed.
* This prevents attackers from submitting fake transfer requests from another website.

## Mitigation

1. Use anti-CSRF tokens: Include anti-CSRF tokens in all sensitive forms and requests. The token should be unpredictable and unique for each request. Upon receiving a form submission or request, verify that the token is present and valid before executing the action.
2. Implement SameSite cookies: Set the SameSite attribute on all cookies to either "Strict" or "Lax" to prevent cross-site requests. This attribute ensures that cookies are only sent with requests to the same site that originated them.
3. Limit HTTP methods: Limit the use of HTTP methods that modify state, such as POST and PUT, to only those requests that require it. Use GET for all read-only operations.
4. Implement re-authentication: For sensitive actions, require the user to re-authenticate with a stronger factor, such as a password or biometric identifier.
5. Use referer headers: Check the Referer header on incoming requests to ensure that they originate from a page on your own site. Be aware that this header is not always reliable and may be stripped by some browsers.

## References

\[CWE -

```
	CWE-352: Cross-Site Request Forgery (CSRF) (4.10)](https://cwe.mitre.org/data/definitions/352.html)
```

[Cross Site Request Forgery (CSRF) | OWASP Foundation](https://owasp.org/www-community/attacks/csrf)

[Cross-Site Request Forgery Prevention - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html)

[Web Security](https://infosec.mozilla.org/guidelines/web\_security#csrf-prevention)

[Spring Security Reference](https://docs.spring.io/spring-security/site/docs/5.5.x-SNAPSHOT/reference/html5/#csrf)

[OWASP CSRFProtector Project | OWASP Foundation](https://owasp.org/www-project-csrfprotector/)

[AngularJS](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection)
