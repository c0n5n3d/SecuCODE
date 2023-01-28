# CWE 79

## What is CWE 79 about?

_**Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**_

The vulnerability occurs **w**hen the user input is handled without performing proper validation or encoding.

## Impact

* Stealing of Sensitive information
* Account Hijacking
* Data Leakage
* Bypassing access controls

## Example with Code Explanation

## `Java`

### Vulnerable Code

```java
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userInput = request.getParameter("search");
        response.setContentType("text/html");
        try {
            response.getWriter().println("<h1>Search Results:</h1>");
            response.getWriter().println("<p>You searched for: " + userInput + "</p>");
        } catch (IOException e) {
            // error handling
        }
    }
}
```

* This code is vulnerable to a Cross-Site Scripting (XSS) attack because
  * It does not properly sanitize the user input before displaying it on the page.
  * The vulnerability lies in the fact that the code uses the **`getParameter()`** method to retrieve the user input, but does not validate or sanitize the input before displaying it on the page using **`response.getWriter().println()`** method.
* This can be mitigated by:
  * Use a library or framework to properly encode user input before it is included in the HTML output. For example, in Java, you can use the **`ESAPI.encoder().encodeForHTML()`** method from the OWASP Enterprise Security API (ESAPI) to encode the user input.
  * Use a whitelist approach to validate user input, allowing only a set of predefined characters or inputs.
  * Use server-side validation.
  * Use a Content Security Policy (CSP) to specify which sources of content are allowed to be loaded by the browser.
  * Use a browser-based XSS auditor.

### Mitigated Code (Best Practice)

```java
import org.owasp.esapi.ESAPI;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userInput = request.getParameter("search");
        response.setContentType("text/html");
        try {
            // Sanitize user input to prevent XSS attacks
            userInput = ESAPI.encoder().encodeForHTML(userInput);
            // Use the sanitized user input in the page
            response.getWriter().println("<h1>Search Results:</h1>");
            response.getWriter().println("<p>You searched for: " + userInput + "</p>");
        } catch (IOException e) {
            // error handling
        }
    }
}
```

* The mitigated code performs:
  * The code is using the `OWASP ESAPI library's encoder` feature to sanitize the user input before using it in the HTML page.
  * The method **`ESAPI.encoder().encodeForHTML(userInput)`** replaces any characters that could be used for XSS attacks with their corresponding safe versions.
  * By using this method, the code ensures that any malicious scripts entered by a user in the "search" parameter will be encoded, making them harmless and unable to execute.

## `.Net`

### Vulnerable Code

```csharp
using System;
using System.Web;

public partial class Search : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string userInput = Request.QueryString["search"];
        Response.Write("<h1>Search Results:</h1>");
        Response.Write("<p>You searched for: " + userInput + "</p>");
    }
}
```

* The above code is vulnerable because it takes `user input` from the `search` query string parameter and includes it directly in the HTML output without properly `sanitizing` it.
* The code then writes the user input directly to the page without any encoding, making it possible for an attacker to inject malicious JavaScript into the page.

### Mitigated Code

```csharp
```

## Mitigation

* We believe the mitigation may require a combination of these techniques.
  * `Input validation:` Ensure that user input is in the expected format and does not contain any malicious code.
  * `Output encoding:` Use a whitelist of allowed characters and encode any other characters using functions like **`encodeForHTML()`**, **`encodeForJavaScript()`** and **`encodeForCSS()`** to prevent malicious code from being executed.
  * `Context-aware output encoding:` Use correct encoding function based on the context of the user input, for example, if the input is being used in a javascript, use **`encodeForJavaScript()`** instead of **`encodeForHTML()`**
  * `Content Security Policy (CSP):` Use a CSP to define a set of rules that limit the sources of content that a web page can load. This can help to prevent malicious code from being executed by the browser.
  * Use a framework or library that has built-in XSS protection: Many web development frameworks and libraries, such as AngularJS, React, and Vue.js, have built-in XSS protection mechanisms that can help to prevent XSS attacks.

## References

[Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)

[The Impact of Cross-Site Scripting Vulnerabilities and their Prevention](https://cypressdatadefense.com/blog/cross-site-scripting-vulnerability/)
