# CWE 91

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

## About CWE ID 91

<mark style="color:green;">**XML Injection (aka Blind XPath Injection)**</mark>

XML Injection, also known as Blind XPath Injection, is a type of security vulnerability that occurs when an application processes XML data from an untrusted source without proper validation or sanitization. Attackers can exploit this weakness by injecting malicious content into the XML data, which could lead to various consequences, such as unauthorized access to sensitive information, denial of service (DoS) attacks, or the execution of arbitrary code.

### Impact

* Information disclosure: Attackers can extract sensitive information from the database or other data sources accessible to the application.
* Data manipulation: Malicious injection can modify, delete, or corrupt data stored in the XML database.
* Denial of Service (DoS): Injected code might cause the application to consume excessive resources or crash, leading to a DoS condition.
* Remote Code Execution: In some cases, attackers may be able to execute arbitrary code, gaining full control over the system.

## Example with Code explanation

### JAVA

Let us consider an example case and understand the CWE 91 with context of Vulnerable code and Mitigated code.

#### _Vulnerable code._

```java
import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;

public class VulnerableXMLParser {
    public static void main(String[] args) {
        try {
            // Read the XML input from an untrusted source (e.g., user input)
            String userInput = "<username>" + args[0] + "</username>";
            
            // Parse the XML document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(userInput.getBytes()));
            
            // Retrieve and print the username from the XML
            Element rootElement = doc.getDocumentElement();
            String username = rootElement.getTextContent();
            System.out.println("Username: " + username);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

```

The provided code is a Java program named "VulnerableXMLParser" that attempts to parse XML input from an untrusted source (e.g., user input) without proper validation, making it vulnerable to XML Injection attacks (CWE ID 91).

Let's break down the vulnerable aspects of the code:

* User Input Concatenation: The program takes user input (provided as command-line arguments) and directly concatenates it into an XML string without any validation or sanitization. The user input is inserted between the and tags, forming an XML element.

```java
String userInput = "<username>" + args[0] + "</username>";
```

This approach can be dangerous because it allows an attacker to inject arbitrary XML elements or entities into the input. If the user supplies malicious XML content, the parser will treat it as valid XML and process it accordingly.

* Lack of XML Input Validation: The program proceeds to parse the XML document using the Java XML parser (DocumentBuilder), but it does not perform any validation or checks on the XML input before parsing it.

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new ByteArrayInputStream(userInput.getBytes()));
```

Since there is no validation, the parser will process whatever XML content is present in the userInput, even if it contains unexpected or malicious elements.

* Retrieving the Username: After parsing the XML document, the code extracts and prints the content between the and tags, assuming it contains a username.

```java
Element rootElement = doc.getDocumentElement();
String username = rootElement.getTextContent();
System.out.println("Username: " + username);
```

This part of the code assumes that the XML contains a valid element, but in reality, the content could be anything, including harmful XML content crafted by an attacker.

The Vulnerable code can be mitigated by:

To mitigate XML Injection vulnerabilities, it is essential to follow secure coding practices:

* Input Validation and Sanitization: Validate and sanitize all user-supplied or untrusted data before using it in XML-related operations.
* Parameterized Queries: Use parameterized XML queries or dedicated XML parsing libraries that handle data securely.
* XML Security Guidelines: Adhere to secure coding guidelines and best practices for handling XML data.
* Proper Error Handling: Implement proper error handling and avoid printing detailed error messages directly to users, as they could reveal sensitive information to potential attackers.

#### _Mitigated code_

```java
import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.xml.sax.SAXException;

public class SafeXMLParser {
    public static void main(String[] args) {
        try {
            // Read the XML input from an untrusted source (e.g., user input)
            String userInput = args[0];
            
            // Validate the XML input to ensure it meets expected criteria
            if (!isValidXML(userInput)) {
                System.err.println("Error: Invalid XML input");
                return;
            }
            
            // Parse the XML document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(userInput.getBytes()));
            
            // Retrieve and print the username from the XML
            Element rootElement = doc.getDocumentElement();
            String username = rootElement.getTextContent();
            System.out.println("Username: " + username);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    // Helper method to validate XML input
    private static boolean isValidXML(String xmlInput) {
        try {
            // Create a new XML Schema object from your schema definition
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new StreamSource(new StringReader("your_schema_definition_here")));
            
            // Create a new Validator for the XML Schema
            javax.xml.validation.Validator validator = schema.newValidator();
            
            // Validate the XML input against the schema
            validator.validate(new StreamSource(new StringReader(xmlInput)));
            
            // If the XML is valid according to the schema, return true
            return true;
        } catch (SAXException | IOException e) {
            // If the XML is invalid or there is an error during validation, return false
            return false;
        }
    }
}

```

Let's Breakdown the mitigation here

* Input Validation: The SafeXMLParser class includes a helper method called isValidXML that performs XML validation on the user-provided input before parsing it. This is a crucial step in preventing XML Injection.
* XML Schema Validation: The code uses an XML Schema to define the expected structure and constraints of the XML input. By validating the input against the XML Schema, the application ensures that the XML data adheres to the predefined format.

```java
// Create a new XML Schema object from your schema definition
SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
Schema schema = factory.newSchema(new StreamSource(new StringReader("your_schema_definition_here")));

```

The actual XML Schema (your\_schema\_definition\_here) needs to be defined based on the expected XML structure for the application. The XML Schema should include specific rules and constraints to ensure that the input contains only valid and expected elements.

* XML Validation: The XML input is then validated against the defined XML Schema using the created javax.xml.validation.Validator.

```java
// Create a new Validator for the XML Schema
javax.xml.validation.Validator validator = schema.newValidator();

// Validate the XML input against the schema
validator.validate(new StreamSource(new StringReader(xmlInput)));

```

If the XML input matches the defined schema and passes validation, the isValidXML method returns true, indicating that the XML is valid. Otherwise, if the input is not well-formed or does not meet the schema's constraints, the method returns false, signifying that the XML is invalid.

* Mitigation of XML Injection: By performing XML validation using a schema, the application ensures that only safe and well-formed XML data is processed. If an attacker attempts to inject malicious XML elements or entities, the validation will fail, preventing the XML Injection vulnerability.

### Python

#### _Vulnerable code._

```python
import xml.etree.ElementTree as ET

def search_items(query):
    # Assume 'query' is taken from user input without proper validation
    xml_data = f'<items><item>{query}</item></items>'
    root = ET.fromstring(xml_data)

    # Process the XML data and return the search results
    # For the sake of this example, let's assume we are just printing the item content
    for item in root.findall('item'):
        print(item.text)

# Assume the 'query' variable is taken from user input
user_input = input("Enter search query: ")
search_items(user_input)

```

In this vulnerable code, the search\_items() function takes user input directly and constructs an XML document without any validation or sanitization. This allows an attacker to inject arbitrary XML content into the query and potentially manipulate the XPath expression.

This can be mitigated by

* Store the token in the user session
* Server need to verify the token respective of the user’s session
* Drop the request if the token is missing or invalid

#### _Mitigated code_

```python
import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils

def search_items(query):
    # Sanitize user input to prevent XML Injection
    sanitized_query = saxutils.escape(query)

    xml_data = f'<items><item>{sanitized_query}</item></items>'
    root = ET.fromstring(xml_data)

    # Process the XML data and return the search results
    # For the sake of this example, let's assume we are just printing the item content
    for item in root.findall('item'):
        print(item.text)

# Assume the 'query' variable is taken from user input
user_input = input("Enter search query: ")
search_items(user_input)

```

This code is mitigated against CWE-91

#### **Input Validation and Sanitization**:

* Always validate and sanitize user input before using it to construct XML data or XPath queries.
* Use input validation techniques like whitelisting, blacklisting, or regular expressions to ensure that user input adheres to the expected format.
* The `saxutils.escape()` function from the `xml.sax.saxutils` module is used to sanitize the user input (`query`) before constructing the XML data. `saxutils.escape()` escapes special characters in the input string, such as `<`, `>`, `&`, `"`, and `'`, by replacing them with their corresponding XML entities. For example, `<` is replaced with `&lt;`, `>` is replaced with `&gt;`, and so on. By performing input validation and sanitization, any potentially malicious XML content provided by the user is treated as regular data and will not be interpreted as executable code. This helps prevent XML Injection.

#### **XML-Specific Escaping**:

* Use XML-specific escaping functions to encode user input before incorporating it into XML data.
* In Python, you can use the `xml.sax.saxutils.escape()` function to escape special characters in the input data.

#### **Validate XML Structure**:

* Validate XML data against a predefined schema or Document Type Definition (DTD) to ensure that it adheres to the expected structure.
* Use Python's built-in `xml.etree.ElementTree` module to parse XML and raise exceptions if the data does not conform to the expected structure.

## Mitigation

1. Input Validation and Sanitization:

* Always validate and sanitize any user input or data coming from untrusted sources before using it in XML-related operations.
* Apply proper input validation techniques, such as whitelisting or regular expressions, to ensure that input adheres to the expected format.

2. Use XML Libraries or APIs:

* Avoid constructing XML documents or XPath expressions manually using string concatenation, especially with user input.
* Instead, use well-established XML libraries or APIs that automatically handle escaping and validation, reducing the risk of injection.

3. Parameterized Queries:

* Whenever possible, use parameterized queries or prepared statements, just like in SQL injection prevention, to handle dynamic XPath expressions safely.
* Parameterized queries separate data from the query logic, preventing malicious input from being treated as executable code.

4. XML-Specific Escaping:

* Use XML-specific escaping functions provided by your programming language or XML libraries to encode special characters in user input.
* These functions will ensure that XML data remains well-formed and secure when incorporating user-provided data.

5. Validate XML Structure:

* Validate incoming XML data against a predefined XML schema or Document Type Definition (DTD) to ensure it adheres to the expected structure.
* Reject or handle malformed XML data appropriately to prevent potential attacks.

6. Principle of Least Privilege:

* Limit the privileges of the XML processing component to only the necessary resources and operations.
* Avoid using XML processing components with elevated privileges, as this could increase the impact of an XML Injection attack.

7. Disable External Entities:

* When parsing XML data, disable the processing of external entities, as they can introduce security risks like XXE (XML External Entity) attacks.
* Many XML libraries have options to disable external entity resolution, and this should be enabled as a security measure.

8. Keep Libraries Updated:

* Regularly update XML parsing libraries and other dependencies to ensure that known vulnerabilities are patched.

9. Logging and Monitoring:

* Implement logging and monitoring mechanisms to detect potential XML Injection attempts and unusual XML-related activities.

10. Security Testing:

* Conduct thorough security testing, including penetration testing, to identify and fix XML Injection vulnerabilities in your application.

## References

{% embed url="https://cwe.mitre.org/data/definitions/91.html" %}

{% embed url="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" %}

{% embed url="https://portswigger.net/web-security/xxe" %}

{% embed url="https://www.hackerone.com/knowledge-center/xxe-complete-guide-impact-examples-and-prevention" %}
