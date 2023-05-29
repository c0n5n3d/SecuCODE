# CWE 22

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

## About CWE ID 22

_<mark style="color:green;">**Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**</mark>_

This Vulnerability occurs when an application does not properly control input access to files and directories outside of its intended directory.

## Impact

* Arbitrary Code Execution.
* Exposure of Sensitive Data.
* Directory Traversal Attacks.
* Denial of Service (DoS) Attacks.

## Example with Code Explanation

## `C`

* Let us consider an example case and understand the CWE 22 with context of Vulnerable code and Mitigated code.

### Vulnerable Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_file(char* filename) {
  char path[100];
  snprintf(path, sizeof(path), "/home/user/data/%s", filename);
  FILE* file = fopen(path, "r");
  if (file) {
    printf("File contents:\n");
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)) {
      printf("%s", buffer);
    }
    fclose(file);
  } else {
    printf("File not found.\n");
  }
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s filename\n", argv[0]);
    exit(1);
  }
  char* filename = argv[1];
  read_file(filename);
  return 0;
}
```

* The Code is Vulnerable since **`read_file`** function takes a filename as input and attempts to read the contents of the file located at **`/home/user/data/filename`**. However, the function does not perform any input validation or sanitization on the **`filename`** parameter, which means that an attacker can pass a specially crafted filename to the function to read files outside of the intended directory.
* Some of the ways the vulnerable code can be mitigated is:
  * `Whitelist-based filtering` Use a whitelist of allowed characters for input validation and disallow any input that contains characters outside of the whitelist.
  * `Input validation and sanitization` All input that could be used to construct file paths should be validated and sanitized to ensure that it does not contain any special characters or escape sequences that can be used to navigate to other directories.
  * `Canonicalization of input paths` Use a canonicalization function to convert input paths to a standardized format before processing them. This can help prevent path traversal attacks by removing any unnecessary or malicious components of the path.
  * `Limited file system access` Limit access to only those directories that are necessary for the application's operation. This can be done by setting appropriate file permissions and access controls.

### Mitigated Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// define a whitelist of allowed filenames
#define WHITELIST_SIZE 5
const char* whitelist[WHITELIST_SIZE] = {"data1.txt", "data2.csv", "data3.json", "data4.xml", "data5.html"};

// check if a filename is in the whitelist
int is_in_whitelist(char* filename) {
  for (int i = 0; i < WHITELIST_SIZE; i++) {
    if (strcmp(filename, whitelist[i]) == 0) {
      return 1; // filename matches one of the whitelist
    }
  }
  return 0; // filename does not match any of the whitelist
}

void read_file(char* filename) {
  char path[100];
  snprintf(path, sizeof(path), "/home/user/data/%s", filename);
  // check if the filename is in the whitelist
  if (!is_in_whitelist(filename)) {
    printf("Access denied.\n");
    return;
  }
  FILE* file = fopen(path, "r");
  if (file) {
    printf("File contents:\n");
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)) {
      printf("%s", buffer);
    }
    fclose(file);
  } else {
    printf("File not found.\n");
  }
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s filename\n", argv[0]);
    exit(1);
  }
  char* filename = argv[1];
  read_file(filename);
  return 0;
}
```

* The Mitigated code does the following:
  * It uses a whitelist method to restrict the allowed filenames that can be accessed. The **`is_in_whitelist`** function checks whether the provided filename matches any of the allowed filenames in the whitelist.
  * If the filename is not in the whitelist, access is denied, and the function returns without reading the file. This effectively mitigates the risk of directory traversal attacks, as only the filenames in the whitelist can be accessed.

## `JAVA`

### Vulnerable Code

```java
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class ReadFile {
    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: java ReadFile <filename>");
            System.exit(1);
        }
        String filename = args[0];
        String path = "/home/user/data/" + filename;
        BufferedReader br = new BufferedReader(new FileReader(path));
        String line;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }
        br.close();
    }
}
```

* The code is vulnerable since it takes a filename as an argument and attempts to read the file from the **`/home/user/data/`** directory. However, it doesn't `validate or sanitize` the input provided by the user, which could potentially allow an attacker to traverse to other directories on the system.
* Some of the ways the Vulnerable code can be mitigated is:
  * `Input Validation` Ensure that any user input is validated and sanitized before it is used to access files. Validate the input to make sure it only contains expected characters or values. Sanitize the input by removing any unwanted characters or values.
  * `Whitelisting` Create a whitelist of acceptable file names, and check that the user input matches one of the acceptable names. This will help prevent the user from specifying a path that leads to an unauthorized file.
  * `Canonicalization` Use a canonical path to access the file. A canonical path is an absolute path without any symbolic links or references to the parent directory (i.e., ".."). By using a canonical path, you can ensure that the file being accessed is the intended file, and not a file in a different directory with a similar name.
  * `File permissions` Set appropriate file permissions to ensure that only authorized users can access or modify files. Limit the permissions to only those users who need access to the file, and deny access to all others.

### Mitigated Code

```java
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileReadExample {
  private static final String BASE_DIRECTORY = "/home/user/data/";
  private static final String[] ALLOWED_EXTENSIONS = { ".txt", ".csv", ".json", ".xml", ".html" };
  private static final int MAX_FILE_SIZE = 1024 * 1024; // 1MB

  public static void main(String[] args) {
    if (args.length != 1) {
      System.out.println("Usage: java FileReadExample <filename>");
      return;
    }
    String filename = args[0];

    // Validate filename
    if (!isValidFilename(filename)) {
      System.out.println("Invalid filename.");
      return;
    }

    // Read file
    String filePath = BASE_DIRECTORY + filename;
    try {
      // Resolve any symbolic links or special elements
      Path realPath = Paths.get(filePath).toRealPath();

      // Check if the real path matches the base directory
      if (!realPath.startsWith(BASE_DIRECTORY)) {
        System.out.println("Invalid file path.");
        return;
      }

      File file = realPath.toFile();
      if (!file.exists() || file.isDirectory()) {
        System.out.println("File not found.");
        return;
      }
      if (file.length() > MAX_FILE_SIZE) {
        System.out.println("File is too large.");
        return;
      }
      BufferedReader reader = new BufferedReader(new FileReader(file));
      String line = null;
      while ((line = reader.readLine()) != null) {
        System.out.println(encodeForHtml(line));
      }
      reader.close();
    } catch (IOException e) {
      System.out.println("Error reading file.");
    }
  }

  private static boolean isValidFilename(String filename) {
    if (filename == null || filename.isEmpty()) {
      return false;
    }
    for (String extension : ALLOWED_EXTENSIONS) {
      if (filename.endsWith(extension)) {
        return true;
      }
    }
    return false;
  }

  private static String encodeForHtml(String input) {
    String output = input.replace("&", "&amp;");
    output = output.replace("<", "&lt;");
    output = output.replace(">", "&gt;");
    output = output.replace("\"", "&quot;");
    output = output.replace("'", "&#x27;");
    output = output.replace("/", "&#x2F;");
    return output;
  }
}
```

* The Mitigated code does the following:
  * Uses a `fixed base directory` to restrict the file access.
  * Validates the filename to ensure it has a valid extension before allowing the file to be accessed.
  * Resolves any `symbolic links` or special elements in the file path to prevent path traversal.
  * Checks that the `resolved path` is still within the base directory.
  * Limits the `maximum size of the file` that can be read to prevent denial-of-service attacks.
  * `Encodes` the contents of the file to protect against cross-site scripting (XSS) attacks when displaying the data in an HTML context.

## `PHP`

### Vulnerable Code

```php
<?php
  $filename = $_GET['file'];
  $file = "/home/user/data/" . $filename;
  if (file_exists($file)) {
    readfile($file);
  } else {
    echo "File not found";
  }
?>
```

* The code is Vulnerable since the filename is taken from the `user input` through the `$_GET` superglobal variable and `directly concatenated` with the base directory to create the file path. This can allow an attacker to provide a specially crafted filename that contains malicious code or that points to a sensitive system file, leading to a path traversal attack.
* Some of the ways the Vulnerable code can be mitigated is:
  * Use `input validation and sanitization` to check if the user-supplied filename is safe to use before processing it.
  * `Restrict` the file types that can be uploaded by checking the file extension or `MIME` type, and only allow known safe `file types`.
  * Use `proper file permissions` to restrict access to the uploaded files only to the web server process or the user running the script.
  * `Limit the file size` of the uploaded files to prevent DoS attacks or server crashes due to excessively large files.

### Mitigated Code

```php
<?php
  define('BASE_DIRECTORY', '/home/user/data/');
  define('ALLOWED_EXTENSIONS', array('txt', 'csv', 'json', 'xml', 'html'));
  define('MAX_FILE_SIZE', 1048576); // 1MB

  $filename = $_GET['file'];

  // Validate filename against a whitelist of allowed values
  $whitelist = array('file1.txt', 'file2.csv', 'file3.json');

  if (!in_array($filename, $whitelist)) {
    echo "Invalid filename." . PHP_EOL;
    exit();
  }

  // Read file
  $filePath = BASE_DIRECTORY . $filename;
  try {
    // Resolve any symbolic links or special elements
    $realPath = realpath($filePath);

    // Check if the real path matches the base directory
    if (strpos($realPath, BASE_DIRECTORY) !== 0) {
        echo "Invalid file path." . PHP_EOL;
        exit();
    }

    // Check the file extension and size
    $extension = pathinfo($realPath, PATHINFO_EXTENSION);
    if (!in_array($extension, ALLOWED_EXTENSIONS)) {
        echo "Invalid file extension." . PHP_EOL;
        exit();
    }

    $fileSize = filesize($realPath);
    if ($fileSize === false) {
        echo "Error getting file size." . PHP_EOL;
        exit();
    }
    if ($fileSize > MAX_FILE_SIZE) {
        echo "File is too large." . PHP_EOL;
        exit();
    }

    // Check if the file exists
    if (!file_exists($realPath)) {
      echo "File not found" . PHP_EOL;
      exit();
    }

    // Read the file
    readfile($realPath);

  } catch (Exception $e) {
    echo "Error reading file." . PHP_EOL;
    exit();
  }
?>
```

* The Mitigated code does the following:
  * `Whitelisting` A whitelist of allowed file names has been implemented, which checks if the requested file is present in the predefined whitelist array. This helps to restrict the user from accessing any arbitrary file.
  * `Check for file extension` The code checks if the file extension of the requested file is one of the allowed extensions. This helps in ensuring that the file is of a valid type.
  * `Check for file size` The code checks the file size before reading it, and restricts the file size to a predefined maximum limit, which helps to prevent a potential DoS attack.
  * `Resolve symbolic links and special elements` The code resolves any symbolic links or special elements in the file path before accessing the file. This helps to prevent the user from accessing files outside the intended directory.

## References

{% embed url="https://cwe.mitre.org/data/definitions/22.html" %}

[What is directory traversal, and how to prevent it? | Web Security Academy](https://portswigger.net/web-security/file-path-traversal)

[Path Traversal | OWASP Foundation](https://owasp.org/www-community/attacks/Path\_Traversal)

[.NET Path Traversal Guide: Examples and Prevention](https://www.stackhawk.com/blog/net-path-traversal-guide-examples-and-prevention/)
