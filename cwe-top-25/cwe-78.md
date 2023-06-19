# CWE 78/77

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

## About CWE ID 78/77

_<mark style="color:green;">**Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')**</mark>_

_<mark style="color:green;">**Improper Neutralization of Special Elements used in a Command ('Command Injection')**</mark>_

The vulnerability arises when an application fails to properly sanitize or validate user input that is used to construct a system command.

## Impact

* System compromise
* Data loss or damage
* Unauthorized data access
* Denial of service

## Example with Code Explanation

## `PHP`

* Let us consider an example case and understand the CWE 78/77 with context of Vulnerable code and Mitigated code.

### Vulnerable Code

```java
<?php
    $filename = $_POST['filename'];
    
    // Execute the "cat" command on the specified file
    $cmd = "cat " . $filename;
    $output = shell_exec($cmd);
    
    // Display the file contents to the user
    echo "<pre>" . $output . "</pre>";
?>
```

* This code is vulnerable to command injection as user input for **`filename`** is concatenated into a string and then passed directly to the **`shell_exec()`** function without any `input validation` or `sanitization`. This can allow an attacker to inject additional commands into the **`cmd`** variable, potentially leading to arbitrary code execution on the underlying system.
* Some of the ways the Vulnerable code can be mitigated is:
  * `Whitelist`: Use a `whitelist` approach to restrict the filenames that can be accessed.
  * `Input validation`: We need to ensure that the **`filename`** parameter only contains valid characters and is in a valid format.
  * `Input sanitization`: We need to sanitize the **`filename`** parameter to remove any special characters that could be used to inject commands or modify the command. For example, we can use the **`escapeshellarg()`** function to escape any special characters in the **`filename`** parameter.
  * `Use Safe API`: Use a safer function like **`file_get_contents()`** to read the contents of the file instead of executing a shell command. This approach removes the need for shell injection altogether and is more secure.

### Mitigated Code

```java
<?php
// Check if the request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    exit('Only POST requests are allowed.');
}

// Check if the filename parameter is provided
if (!isset($_POST['filename'])) {
    http_response_code(400); // Bad Request
    exit('Please provide a filename parameter.');
}

// Get the filename parameter
$filename = $_POST['filename'];

// Define a whitelist of allowed file names
$whitelist = array("file1.txt", "file2.txt", "file3.txt");

// Check if the filename parameter is in the whitelist
if (!in_array($filename, $whitelist)) {
    http_response_code(403); // Forbidden
    exit('Access denied.');
}

// Construct the full path to the file
$file_path = "/path/to/files/" . $filename;

// Check if the file exists
if (!file_exists($file_path)) {
    http_response_code(404); // Not Found
    exit('File not found.');
}

// Use file_get_contents to read the contents of the file
$content = file_get_contents($file_path);

// Display the file contents to the user
echo "<pre>" . htmlspecialchars($content, ENT_QUOTES, 'UTF-8') . "</pre>";
?>
```

* The Mitigated code does the following:
  * The code does not use any potentially vulnerable functions that take `user input` and execute it as `operating system commands`.
  * The code uses a whitelist approach to restrict the filenames that can be accessed.
  * The code performs basic input validation on the **`filename`** parameter to ensure that it is provided and not empty.

## `Java`

### Vulnerable Code

```java
import java.io.*;

public class CommandExecutor {
    
    public static void main(String[] args) throws IOException {
        String command = args[0];
        String line = "";
        
        // Execute the specified command using Runtime.exec()
        Process process = Runtime.getRuntime().exec(command);
        
        // Read the output of the command from the input stream
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        
        while ((line = inputReader.readLine()) != null) {
            System.out.println(line);
        }
    }
    
}
```

* The Vulnerable code reads a command to execute from the first command-line argument and passes it to the **`Runtime.exec()`** method without any `input validation or sanitation`. An attacker could supply a malicious command as the argument, potentially allowing them to execute arbitrary code on the system.
* Some of the ways the Vulnerable code can be mitigated is:
  * Input validation: `Validate and sanitize` user input before using it to execute commands. This includes checking the input for any unexpected or invalid characters and only allowing a predefined set of characters.
  * Least privilege: When executing commands or accessing files, ensure that the process has the `minimum necessary permissions`. This reduces the risk of attackers gaining access to sensitive information or resources.
  * Use a whitelist of allowed commands: Instead of validating user input to block certain characters, you can create a `whitelist of allowed commands` that the application can execute. This way, even if an attacker manages to inject code, it won't execute because it's not in the allowed list of commands.

### Mitigated Code

```java
import java.io.*;
import java.util.*;

public class Example {

    public static void main(String[] args) {
        // Check if the request method is POST
        if (!"POST".equals(request.getMethod())) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Only POST requests are allowed.");
            return;
        }

        // Check if the filename parameter is provided
        String filename = request.getParameter("filename");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Please provide a filename parameter.");
            return;
        }

        // Validate the filename parameter
        if (!isValidFilename(filename)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied.");
            return;
        }

        // Construct the full path to the file
        String filePath = "/path/to/files/" + filename;

        // Check if the file exists and is a regular file
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found.");
            return;
        }

        // Use a buffered reader to read the contents of the file
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));
            String line = null;
            StringBuilder sb = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            response.getWriter().write(sb.toString());
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server error.");
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    private static boolean isValidFilename(String filename) {
        // Define a whitelist of allowed file names
        List<String> whitelist = Arrays.asList("file1.txt", "file2.txt", "file3.txt");

        // Check if the filename parameter is in the whitelist
        return whitelist.contains(filename);
    }
}
```

* The Mitigated code does the following:
  * The code only allows access to a `predefined list of files` and doesn't allow access to any other file on the server.
  * The code ensures that the `provided file exists` and is a regular file before attempting to read it. It also uses a `buffered reader` to read the contents of the file, which is a safe way to read files.
  * It checks if the request method is POST, checks if the filename parameter is provided, and validates the filename parameter.

## `C`

### Vulnerable Code

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char filename[100];
    FILE *fp;
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    strcpy(filename, argv[1]);
    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Unable to open file: %s\n", filename);
        return 1;
    }
    // read and process file contents
    fclose(fp);
    return 0;
}
```

The code is vulnerable as the program takes a filename as a command-line argument and attempts to open the file using **`fopen()`**. However, there is no `validation or sanitization` of the filename input, so an attacker could craft a malicious filename that includes special characters or escape sequences to bypass any input filtering and access or modify sensitive files on the system.

* Some of the ways the vulnerable code can be mitigated is:
  * `Whitelisting` can be used to restrict the input to only accept certain values.
  * One of the most important mitigations is to validate any input that is being used in a potentially dangerous function such as **`strcpy()`** or **`fopen()`**
  * `Sanitization` involves removing or escaping any potentially dangerous characters or sequences from input before it is used in a function.

### Mitigated Code

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char **argv) {
    char filename[100];
    FILE *fp;
    const char *allowed_filenames[] = { "file1.txt", "file2.txt", "file3.txt", NULL };
    int i;

    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // validate filename against whitelist
    for (i = 0; allowed_filenames[i] != NULL; i++) {
        if (strcmp(argv[1], allowed_filenames[i]) == 0) {
            break;
        }
    }

    if (allowed_filenames[i] == NULL) {
        printf("Invalid filename: %s\n", argv[1]);
        return 1;
    }

    // validate filename against allowed characters
    for (i = 0; argv[1][i] != '\0'; i++) {
        if (!isalnum(argv[1][i]) && argv[1][i] != '.' && argv[1][i] != '_') {
            printf("Invalid character in filename: %c\n", argv[1][i]);
            return 1;
        }
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        printf("Unable to open file: %s\n", argv[1]);
        return 1;
    }

    // read and process file contents
    fclose(fp);
    return 0;
}
```

* The Mitigated code does the following:
  * The user-controlled input is the filename passed as a command-line argument. However, this input is validated against a `whitelist` of allowed filenames and checked to ensure that it contains only alphanumeric characters, periods, and underscores.
  * The code does not use any shell metacharacters that could be used to execute arbitrary commands. For example, the code does not use **`system()`** or any other function that could be used to execute a shell command.
  * The code does not use system-level commands that could be vulnerable to command injection. The only system-level function called is **`fopen()`**, which is a library function that opens a file for reading.

## References

[OS Command Injection Defense - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/OS\_Command\_Injection\_Defense\_Cheat\_Sheet.html)

{% embed url="https://cwe.mitre.org/data/definitions/77.html" %}

{% embed url="https://cwe.mitre.org/data/definitions/78.html" %}
