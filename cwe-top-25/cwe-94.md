# CWE 94

<details>

<summary>Disclaimer</summary>

* <mark style="color:red;">The code provided is for</mark> <mark style="color:red;">`**educational purposes**`</mark> <mark style="color:red;">only and should not be used in a</mark> <mark style="color:red;">`**production environment**`</mark> <mark style="color:red;">without proper review and testing.</mark>

<!---->

* <mark style="color:red;">The provided code should be regarded as</mark> <mark style="color:red;">`**best practice**`</mark><mark style="color:red;">. There are also several ways to remediate the Vulnerabilities.</mark>

<!---->

* <mark style="color:red;">The code provided</mark> <mark style="color:red;">`**may contain vulnerabilities**`</mark> <mark style="color:red;">that could be exploited by attackers, and is intended to be used as a learning tool to help improve security awareness and best practices.</mark>

<!---->

* <mark style="color:red;">The mitigations provided are intended to address</mark> <mark style="color:red;">`**specific vulnerabilities**`</mark> <mark style="color:red;">in the code, but may not be effective against all potential attack vectors or scenarios.</mark>

<!---->

* <mark style="color:red;">The code provided is not</mark> <mark style="color:red;">`**guaranteed to be secure or free**`</mark> <mark style="color:red;">from all vulnerabilities, and should be reviewed and tested thoroughly before being used in a production environment.</mark>

<!---->

* <mark style="color:red;">The code provided is</mark> <mark style="color:red;">`**not a substitute for professional security**`</mark> <mark style="color:red;">advice or guidance, and users should consult with a qualified security professional before implementing any security measures.</mark>

<!---->

* <mark style="color:red;">The authors and contributors of the code provided</mark> <mark style="color:red;">`**cannot be held responsible**`</mark> <mark style="color:red;">for any damages or losses resulting from the use of this code.</mark>

<!---->

* <mark style="color:red;">The code provided is provided "as is" without any warranties, express or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose.</mark>

<!---->

* <mark style="color:red;">We do not have any sponsors or financial interests in any specific products or services, and the information provided is based solely on our own knowledge and experience.</mark>

<!---->

* <mark style="color:red;">The vulnerable and mitigated code samples provided on our platform are generated with the help of AI and sourced from the internet. We have made every effort to ensure that the code is accurate and up-to-date, but we cannot guarantee its correctness or completeness. If you notice that any of the code samples belong to you and you wish for it to be removed, please contact us and we will take appropriate action. We also apologize for any inconvenience caused and are committed to giving appropriate credit to the respective authors.</mark>

</details>

## About CWE ID 94

<mark style="color:green;">**Improper Control of Generation of Code ('Code Injection')**</mark>

This Vulnerability occurs when an application or system allows an attacker to inject and execute arbitrary code in target application.

## Impact

* Remote Code Execution (RCE)
* Data Theft or Manipulation
* Privilege Escalation
* Denial of Service (DoS)
* Cross-Site Scripting (XSS)
* Command Execution
* Application Defacement

## Example with Code Explanation

Let us consider an example case and understand the CWE 94 with context of Vulnerable code and Mitigated code.

## `PHP`

### Vulnerable Code

```php
<?php
  // Assume $user_input contains user-supplied data
  $user_input = $_GET['user_input'];
  
  // Vulnerable code
  eval($user_input);
?>
```

The above script takes user input from the query string (GET parameter named 'user\_input') and directly executes it using the **`eval()`** function.

This code is vulnerable to code injection. An attacker can input PHP code directly into the URL, and it will be executed in the context of the script. For example, if an attacker inputs **`phpinfo();`**, it would execute the **`phpinfo()`** function, potentially revealing sensitive information about the server's PHP configuration.

Some of the ways the above Vulnerable code can be mitigated is:

* **Avoid Using `eval()`**: Refrain from using **`eval()`** to execute arbitrary code provided by users. This function can lead to security vulnerabilities.
* **Input Validation and Sanitization**: Validate and sanitize user input to ensure it adheres to expected formats and constraints. This prevents the injection of malicious code.
* **Whitelist Allowed Functions or Commands**: Allow only specific, safe functions or commands to be executed. Reject any input that doesn't match the allowed list.
* **Use Appropriate Security Libraries or Modules**: Utilize security libraries or modules that offer secure alternatives to potentially dangerous functions like **`eval()`**.
* **Implement Least Privilege Principle**: Ensure code executes with the least privileges necessary for its task. Limit the potential impact of any successful injection.

### Mitigated Code

```php
<?php
  // Assume $user_input contains user-supplied data
  $user_input = $_GET['user_input'];
  
  // Mitigated code
  $user_input = htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8'); // HTML escape user input
  
  // Validate user input (for example, ensuring it's a valid integer)
  if (is_numeric($user_input)) {
      $result = my_custom_function($user_input); // Process user input safely
      echo "Result: $result";
  } else {
      echo "Invalid input.";
  }
?>
```

The Mitigated code does the following:

* **Input Validation and Sanitization**:
  * We use **`htmlspecialchars`** to HTML escape user input. This ensures that any special characters are safely converted to their corresponding HTML entities, preventing XSS attacks.
* **Validate User Input**:
  * We use **`is_numeric()`** to validate that the user input is a valid numeric value. This helps prevent the execution of arbitrary code.
* **Process User Input Safely**:
  * If the input passes validation, it is used in a safe context, such as being passed as an argument to **`my_custom_function()`**. This function should handle the input securely.

## `Perl`

### Vulnerable Code

```jsx
#!/usr/bin/perl

use strict;
use warnings;

print "Enter a command to execute: ";
my $user_input = <STDIN>;
chomp($user_input);

# Vulnerable code: Executes the user-input command using backticks without validation
my $output = `$user_input`;

# Display the output of the command
print "Command output:\n$output\n";
```

In the above example, the script prompts the user to enter a command, and the user input is directly incorporated into the command using backticks. This is a code injection vulnerability, as an attacker could provide malicious input to execute arbitrary commands.

Some of the ways the Vulnerable code can be mitigated is:

* **Avoid Using `eval` with Unvalidated Input:**
  * Do not use the **`eval`** function with `unvalidated` or `unsanitized` user input, especially when dealing with dynamic code execution.
* **Use Safe Alternatives to System Commands:**
  * Avoid directly using `system commands` with `user input`. Whenever possible, use Perl modules or libraries for performing file operations or interacting with external programs.
* **Validate and Sanitize User Input:**
  * Validate and sanitize all user inputs to ensure they conform to expected formats.
* Use regular expressions or specific validation functions to ensure that input adheres to the expected patterns.
* **Use Quotemeta for Command Arguments:**
  * If user input must be included in system commands, use the **`quotemeta`** function to escape special characters and prevent unintended command execution.

```perl
perlCopy code
my $safe_input = quotemeta($user_input);
system("command $safe_input");

```

*   **Use Safe Shell Execution Modules:**

    * Consider using modules like **`String::ShellQuote`** to properly quote and escape user input when executing commands. This can help prevent command injection vulnerabilities.

    ```perl
    perlCopy code
    use String::ShellQuote;
    my $quoted_input = shell_quote($user_input);
    system("command $quoted_input");

    ```

### Mitigated Code

```jsx
#!/usr/bin/perl

use strict;
use warnings;
use String::ShellQuote;

print "Enter a command to execute: ";
my $user_input = <STDIN>;
chomp($user_input);

# Mitigated code: Uses String::ShellQuote to properly quote and escape user input
my $quoted_input = shell_quote($user_input);
my $output = `$quoted_input`;

# Display the output of the command
print "Command output:\n$output\n";
```

The Mitigated code does the following:

* **Use `String::ShellQuote`:**
  * The **`String::ShellQuote`** module is used to properly quote and escape the user input. This helps prevent special characters in the input from being interpreted as part of the command.
* **Chomping User Input:**
  * **`chomp`** is used to remove the newline character from user input to ensure a clean command.
* **Avoiding Direct Execution of Unvalidated Input:**
  * While this example still uses backticks to execute the command, the use of **`String::ShellQuote`** helps mitigate the risk by ensuring proper quoting and escaping.

## Python

### Vulnerable Code

```jsx
#!/usr/bin/env python

import os

print("Enter a filename: ")
filename = input().strip()

# Vulnerable code: Executes a system command with unvalidated input
os.system("cat " + filename)
```

In this example, the program prompts the user to enter a filename, and the user input is directly concatenated into the system command using string concatenation (**`"cat " + filename`**). This is vulnerable to code injection, as an attacker could provide malicious input to execute arbitrary commands.

Some of the ways the Vulnerable code can be mitigated is:

* **Using `subprocess.run` with Shell=False:**
  * Instead of using **`os.system`** or **`subprocess.call`**, you can use the **`subprocess.run`** function with **`shell=False`** to avoid shell injection:
* **Input Sanitization:**
  * Apply input sanitization techniques to remove or escape characters that could be used for injection.
* **Explicitly Separate Commands and Arguments:**
  * Explicitly separate commands and arguments to ensure that user input is treated as data, not executable code.
* **Input Validation:**
  * Implement input validation to ensure that the user input adheres to expected patterns. This helps reject malicious input before it reaches the command execution

### Mitigated Code

```jsx
#!/usr/bin/env python

import subprocess
import shlex

def validate_filename(filename):
    # Add proper validation logic here
    # For example, check if the filename has valid characters
    return all(c.isalnum() or c in ('.', '_', '-') for c in filename)

print("Enter a filename: ")
filename = input().strip()

# Mitigated code: Input validation and safe subprocess execution
if validate_filename(filename):
    try:
        sanitized_filename = shlex.quote(filename)
        subprocess.run(["cat", sanitized_filename], shell=False, check=True)
    except subprocess.CalledProcessError:
        print("Error: Command failed")
else:
    print("Error: Invalid filename")
```

* The Mitigated code does the following
* **Input Validation:**
  * The **`validate_filename`** function checks if the filename contains only alphanumeric characters, dots, underscores, and hyphens. This validation ensures that the user input adheres to an expected pattern and rejects any input that could potentially be used for injection.
* **Safe Quoting with `shlex.quote`:**
  * The **`shlex.quote`** function is used to properly quote the filename before incorporating it into the command. This ensures that special characters in the filename are appropriately escaped, preventing them from being interpreted as shell metacharacters.
* **Use of `subprocess.run` with `shell=False`:**
  * The code uses **`subprocess.run`** with **`shell=False`** to execute the command. By avoiding the use of a shell (**`shell=True`**), the script prevents shell injection vulnerabilities. Each element of the command is treated as a separate argument, eliminating the risk of unintentional command execution due to unescaped special characters.
* **Error Handling:**
  * The code includes error handling using a **`try-except`** block to catch potential failures in command execution. This is a good practice for robustness, ensuring that the script gracefully handles errors and avoids unintended consequences.

## Common Mitigations

* Some Common Mitigation techniques include:
  * **Input Validation:**
    * Implement thorough input validation to ensure that user input adheres to expected formats and ranges. Validate input at the client side (if applicable) and server side to prevent the submission of malicious or unexpected input.
  * **Avoid Dynamic Code Execution:**
    * Minimize the use of functions like **`eval`** or similar constructs that dynamically execute code based on user input. Evaluate safer alternatives that don't involve direct code execution.
  * **Use Safe APIs and Libraries:**
    * Utilize safe APIs and libraries provided by the programming language or third-party libraries that handle data manipulation, file operations, and other potentially risky tasks in a secure manner.
  * **Secure File Handling:**
    * When dealing with file operations, avoid direct concatenation of user input into file paths or commands. Ensure that file paths are validated and sanitized to prevent directory traversal attacks.
  * **Safe Command Execution:**
    * If executing system commands, use functions or libraries that allow you to pass arguments separately from the command. Avoid using shell-executing functions with unvalidated user input.
  * **Output Encoding:**
    * When rendering user input in HTML or other output formats, apply proper output encoding to prevent Cross-Site Scripting (XSS) attacks. Use encoding functions specific to the output context (e.g., HTML encoding, URL encoding).
  * **Update Dependencies:**
    * Keep all dependencies, including programming languages, frameworks, and libraries, up to date to benefit from security patches and fixes.

## References

{% embed url="https://cwe.mitre.org/data/definitions/94.html" %}

[Code Injection | OWASP Foundation](https://owasp.org/www-community/attacks/Code\_Injection)

[A Pentester’s Guide to Code Injection | Cobalt](https://www.cobalt.io/blog/a-pentesters-guide-to-code-injection)
