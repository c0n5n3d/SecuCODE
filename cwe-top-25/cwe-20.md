# CWE 20

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

## What is CWE 20 about?

_<mark style="color:green;">**Improper Input Validation**</mark>_

This Vulnerability occurs when software does not properly validate or sanitize input received from users or other sources.

## Impact

* Arbitrary code execution, data modification, or destruction.
* Injection of malicious input.
* Privilege escalation, administrative access, and network pivoting.
* Phishing, social engineering, and other types of user manipulation.
* Persistent access, data exfiltration.

## Example With Code Explanation

## `PHP`

* Let us consider an example case and understand the CWE 20 with context of Vulnerable code and Mitigated code.

### Vulnerable Code

```php
$username = $_GET['username'];

$sql = "SELECT * FROM users WHERE username = '" . $username . "'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
  while ($row = mysqli_fetch_assoc($result)) {
    echo "Welcome " . $row['username'] . "!";
  }
} else {
  echo "User not found.";
}
```

* The Vulnerable code directly uses the user input from the **`$_GET`** superglobal without any `validation or sanitization`.Specifically, the **`username`** value is used in a SQL query without any checks to ensure that it contains only expected values. An attacker could use techniques such as comment injection, UNION-based attacks, or other SQL injection methods to modify or retrieve sensitive data from the database.

Some of the ways the Vulnerable code can be mitigated is:

* Use `proper input validation and sanitization` techniques to ensure that user input contains only expected values.
* Avoid using user input `directly in SQL queries` without any validation or sanitization.
* Use `prepared statements` with parameterized queries to ensure that user input is properly validated and sanitized before it is used in the query.

### Mitigated Code

```php
// Assume that HTTPS protocol is used and $conn is a valid mysqli connection object

// Step 1: Use POST method to receive user input from the request body
$username = $_POST['username'];

// Step 2: Validate input
if (!ctype_alnum($username)) {
    echo "Invalid input.";
    exit;
}

// Step 3: Sanitize input
$username = mysqli_real_escape_string($conn, $username);

// Step 4: Use prepared statements to execute safe queries
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
  while ($row = $result->fetch_assoc()) {
    // Step 5: Use output encoding to display data safely
    echo "Welcome " . htmlspecialchars($row['username']) . "!";
  }
} else {
  echo "User not found.";
}
```

The above code is mitigated against:

* The code uses `prepared statements` with a parameterized query to safely execute the SQL query on the database. This ensures that the input is treated as data and not as part of the SQL query.
* The input is validated using the **`ctype_alnum()`** function, which ensures that it contains only alphanumeric characters. This prevents attackers from using special characters or SQL keywords to bypass the input validation process.
* The input is sanitized using the **`mysqli_real_escape_string()`** function, which removes any special characters or SQL keywords that could be used in a SQL injection attack.
* The code uses output encoding to display data safely. The **`htmlspecialchars()`** function converts special characters to their HTML entities, preventing attackers from injecting malicious code into the output.

## `C`

### Vulnerable Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void display_user(char *username) {
    char sql_query[1000];
    sprintf(sql_query, "SELECT * FROM users WHERE username='%s'", username);
    // Execute the SQL query and display the result
}

int main() {
    char username[100];
    printf("Enter username: ");
    scanf("%s", username);
    display_user(username);
    return 0;
}
```

* The **`scanf()`** function is used to read user input from standard input, which does not enforce any constraints on the input. The user input is then passed directly into an SQL query without any `input validation or sanitization`, allowing an attacker to inject malicious SQL code into the query.
* Some of the ways the above code can be mitigated is:
  * Use **`fgets()`** or **`scanf()`** function with proper bounds checking to read user input from standard input.
  * Validate the user input to ensure that it only contains alphanumeric characters.
  * Use a `parameterized query` or `prepared statement` to execute the SQL query, which ensures that the user input is properly escaped and prevents SQL injection attacks.
  * Properly `handle errors and exceptions` to prevent unintended behavior or security issues.

### Mitigated code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char username[20];
    // Step 1: Receive user input
    printf("Enter username: ");
    scanf("%19s", username);

    // Step 2: Validate input
    for (int i = 0; i < strlen(username); i++) {
        if (!isalnum(username[i])) {
            printf("Invalid input.\n");
            exit(1);
        }
    }

    // Step 3: Use prepared statements to execute safe queries
    char query[100] = "SELECT * FROM users WHERE username = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    // Step 4: Bind parameters to the prepared statement
    rc = sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to bind parameter: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    // Step 5: Execute the prepared statement
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        printf("Welcome %s!\n", sqlite3_column_text(stmt, 0));
    } else if (rc == SQLITE_DONE) {
        printf("User not found.\n");
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}
```

The Mitigated Code does the following:

* `Validation`: The user input is validated to ensure that it only contains alphanumeric characters. This mitigates the risk of SQL injection attacks by preventing malicious input from being executed as SQL commands.
* `Prepared statements`: The code uses prepared statements to execute safe queries, which mitigates the risk of SQL injection attacks by separating the SQL code from the user input.
* `Parameter binding`: The user input is passed as a parameter to the prepared statement using **`sqlite3_bind_text()`**. This mitigates the risk of SQL injection attacks by ensuring that the input is properly escaped and encoded before being executed as part of the SQL statement.
  * `Error handling`: The code checks the return value of **`sqlite3_step()`** to determine if the query execution was successful or not. This helps to prevent errors and vulnerabilities caused by improperly formatted queries or database errors.

## `Java`

### Vulnerable Code

```java
import java.sql.*;

public class UserDatabase {

    public void getUserData(String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username='" + username + "'";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/mydatabase", "root", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        while (rs.next()) {
            String email = rs.getString("email");
            System.out.println("Email: " + email);
        }
        conn.close();
    }

    public static void main(String[] args) {
        UserDatabase db = new UserDatabase();
        try {
            db.getUserData(args[0]);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

}
```

The above code is Vulnerable as the **`username`** parameter is concatenated directly into the SQL query using string concatenation, which can allow an attacker to inject their own SQL code into the query. It constructs an SQL query using unvalidated user input in the **`getUserData()`** method. This type of attack is known as SQL injection and can be used to read, modify, or delete data in the database, as well as perform other malicious actions.

* Some of the ways the Vulnerable code can be mitigated is:
  * Use `parameterized queries` instead of directly concatenating user input into SQL statements. This can help prevent SQL injection by ensuring that user input is properly sanitized and escaped before being used in the SQL statement.
  * `Validate and sanitize user input` to ensure that it only contains expected characters and format. This can help prevent attacks that attempt to inject SQL code or other malicious input.
  * Implement `input validation and sanitization` as close to the point of user input as possible. This can help ensure that user input is properly handled before it is passed to other parts of the application, such as the database.

### Mitigated Code

```java
import java.sql.*;

public class UserDatabase {

    public void getUserData(String username) throws SQLException {
        // Check if username is null or empty
        if (username == null || username.isEmpty()) {
            System.out.println("Invalid username.");
            return;
        }
        // Check if username matches a certain pattern or length
        // For example, assume that usernames are alphanumeric and between 4 and 16 characters long
        String regex = "^[a-zA-Z0-9]{4,16}$";
        if (!username.matches(regex)) {
            System.out.println("Invalid username.");
            return;
        }
        // Sanitize username by removing any special characters or whitespace
        // For example, replace all non-alphanumeric characters with an underscore
        username = username.replaceAll("[^a-zA-Z0-9]", "_");

        String query = "SELECT * FROM users WHERE username=?";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/mydatabase", "root", "password");
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();
        while (rs.next()) {
            String email = rs.getString("email");
            System.out.println("Email: " + email);
        }
        conn.close();
    }

    public static void main(String[] args) {
        UserDatabase db = new UserDatabase();
        try {
            db.getUserData(args[0]);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

}
```

The Mitigated code does the following:

* `Validates the user input` against a specific pattern to ensure it meets the expected format.
* `Sanitizes the user input` by replacing any special characters or whitespace with an underscore.
* `Uses a parameterized query` with a prepared statement, which helps to prevent SQL injection attacks.

## References

{% embed url="https://cwe.mitre.org/data/definitions/20.html" %}

[Input Validation - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Input\_Validation\_Cheat\_Sheet.html)
