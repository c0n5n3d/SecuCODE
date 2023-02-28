# CWE 79

<mark style="color:red;"></mark>[<mark style="color:red;">Disclaimer</mark>](../readme/disclaimer.md)<mark style="color:red;"></mark>

## What is CWE 79 about?

_**Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**_

The vulnerability occurs **w**hen the user input is handled without performing proper validation or encoding.

## Impact

* Stealing of Sensitive information
* Account Hijacking
* Data Leakage
* Bypassing access controls

## Example with Code Explanation

## `Javascript`

* Let us consider an example case and understand the CWE 787 with context of Vulnerable code and Mitigated code.

### Vulnerable Code

```jsx
<html>
<head>
  <script>
    function showMessage() {
      var message = document.getElementById("message").value;
      document.getElementById("display").innerHTML = message;
    }
  </script>
</head>

<body>
  <textarea id="message"></textarea>
  <button onclick="showMessage()">Show Message</button>
  <div id="display"></div>
</body>
</html>
```

* This code is vulnerable to XSS because,
  * User input is taken directly from the **`message`** textarea without any validation or sanitization.
  * The user input is directly assigned to the **`innerHTML`** property of the **`display`** element, which can cause malicious code to be executed.
  * The **`onclick`** event handler is set to **`showMessage()`**, which is executed whenever the button is clicked and the user input is displayed.
* Some of the ways the vulnerable code can be mitigated is
  * `Input validation`: Check the user input for any characters or patterns that could indicate a potential XSS attack. For example, you could check for the presence of angle brackets **`<`** and **`>`**, or script tags **`<script>`**. If any malicious characters or patterns are found, the input should be rejected.
  * `Input sanitization`: Remove any characters or patterns from the user input that could indicate a potential XSS attack. For example, you could replace angle brackets **`<`** and **`>`** with their HTML entity representation **`&lt;`** and **`&gt;`**.
  * `Encoding`: Convert any characters in the user input that have a special meaning in HTML into their HTML entity representation. For example, you could encode **`<`** as **`&lt;`** and **`>`** as **`&gt;`**.
  * `Use a library`: There are libraries available that can help to prevent XSS attacks. For example, you could use the DOMPurify library to sanitize the user input and remove any potential XSS payloads.

### Mitigated Code

```jsx
<html>
<head>
  <script src="https://cdn.jsdelivr.net/npm/dompurify@2.4.3/dist/purify.min.js"></script>
  <script>
    function showMessage() {
      var message = document.getElementById("message").value;
      var sanitizedMessage = DOMPurify.sanitize(message, {SAFE_FOR_JQUERY: true});
      var encodedMessage = encodeURIComponent(sanitizedMessage);
      document.getElementById("display").innerHTML = encodedMessage;
    }
  </script>
</head>

<body>
  <textarea id="message"></textarea>
  <button onclick="showMessage()">Show Message</button>
  <div id="display"></div>
</body>
</html>
```

* The mitigated code does the following:
  * The **`showMessage`** function retrieves the user input from the text area with **`document.getElementById("message").value`**
  * The input is then sanitized using **`DOMPurify.sanitize(message, {SAFE_FOR_JQUERY: true})`**. The **`SAFE_FOR_JQUERY`** option indicates that the sanitized content can be safely used with jQuery.
  * The encoded message is then set as the inner HTML of a div with **`document.getElementById("display").innerHTML = encodedMessage`**

💡 It is important to keep in mind that no sanitization library is perfect and new vulnerabilities may be discovered in the future, so it is always a good idea to keep the library up to date and to continue to review the code for potential vulnerabilities.

## `.Net`

### Vulnerable Code

```csharp
using System;
using System.Web;
using System.Web.UI;

namespace WebApplication1
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string userInput = Request.QueryString["message"];
            labelDisplay.Text = userInput;
        }
    }
}
```

* This code is vulnerable to XSS attacks because it does not perform any kind of `validation`, `escaping`, or `encoding` on the user input from the query string, which could contain malicious JavaScript code. The user input is directly assigned to the **`Text`** property of a label control, which can be interpreted as HTML and executed by the browser.
* Some of the ways the Vulnerable code can be mitigated is:
  * `Input Validation`: Validate user input to ensure that it conforms to the expected format and data type. Remove any malicious input, such as JavaScript code, before displaying it on the page.
  * `HTML Encoding`: When displaying user input on a web page, use HTML encoding to convert special characters into their corresponding HTML entities. This prevents any malicious code from being executed in the browser.
  * `Output Escaping`: If the user input is used in a different context, such as within an HTML attribute or a JavaScript context, use the appropriate escaping function to prevent XSS.
  * `Content Security Policy (CSP)`: Use a Content Security Policy header to specify which sources of content are allowed to be loaded within a web page. This helps to prevent XSS by limiting the types of content that can be executed in the browser.

### Mitigated Code

```csharp
using System;
using System.Web;
using System.Web.UI;

namespace WebApplication1
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string userInput = Request.QueryString["message"];

            // Length Limitation
            if (userInput != null && userInput.Length > 100)
            {
                userInput = userInput.Substring(0, 100);
            }

            // Whitelisting & Output Escaping
            userInput = HttpUtility.HtmlEncode(userInput);

            labelDisplay.Text = userInput;
        }
```

* The mitigated code does the following:
  * `Input Validation`: The user input is obtained from the query string parameter `message` and is assigned to the `userInput` variable.
  * `Output Escaping`: The user input is passed through `HttpUtility.HtmlEncode()` method which escapes special characters in the input, making it safe to display as plain text.

## `Python`

### Vulnerable Code

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    message = request.args.get("message")
    return "<html><body><h1>" + message + "</h1></body></html>"

if __name__ == "__main__":
    app.run()
```

* The code is Vulnerable to Cross Site Scripting because the user input is obtained from the query string parameter `message` and is directly concatenated with the HTML response without any `validation` or `escaping`. This can allow an attacker to inject malicious code into the HTML response and execute it in the context of the user's browser, leading to a Cross-Site Scripting.
* This code can be mitigated by:
  * `Input Validation`: Check user input for malicious content and reject it if necessary. A common approach is to use a whitelist of allowed characters, rather than a blacklist of disallowed characters.
  * `Output Escaping`: Escape characters that have special meaning in HTML, such as **`<`** and **`>`**. This will prevent user-supplied content from being interpreted as HTML by the browser.
  * `Content Security Policy (CSP)`: Use a Content Security Policy header to specify which sources of content are allowed to be loaded within a web page. This helps to prevent XSS by limiting the types of content that can be executed in the browser.

### Mitigated Code

```python
from flask import Flask, request
import re
import html

app = Flask(__name__)

@app.route("/")
def home():
    message = request.args.get("message")
    
    # Input Validation
    if message is not None:
        message = message.strip()
        if not re.match("^[a-zA-Z0-9]+$", message):
            message = "Invalid input"
    else:
        message = ""
    
    # Output Escaping
    message = html.escape(message)
    
    return "<html><body><h1>" + message + "</h1></body></html>"

if __name__ == "__main__":
    app.run()
```

* The Mitigated Code does the following:
  * `Input validation`: The code performs input validation by checking if the input is not **`None`** and then stripping it with **`message.strip()`**. It then uses a regular expression to validate the input, allowing only certain characters (alphanumeric characters) to be used.
  * `Output escaping`: The code uses **`html.escape()`** to escape any special characters in the output, preventing malicious payloads from being executed as code.

## References

[Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)

[The Impact of Cross-Site Scripting Vulnerabilities and their Prevention](https://cypressdatadefense.com/blog/cross-site-scripting-vulnerability/)

[Cross Site Scripting Prevention - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html)
