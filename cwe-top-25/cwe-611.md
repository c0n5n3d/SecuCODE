# CWE 611

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

## About CWE 611

_<mark style="color:green;">**Improper Restriction of XML External Entity Reference**</mark>_

This weakness occurs when an application processes XML data without properly preventing the inclusion or processing of `external entities`, which can lead to various security issues, including XML External Entity (XXE) attacks.

## Impact

* Information Disclosure
* Denial of Service (DoS
* Remote Code Execution
* Server-Side Request Forgery (SSRF)
* Blind XXE
* Data Modification or Deletion
* System Compromise

## Example with Code Explanation

Let us consider an example case and understand the CWE 611 with context of Vulnerable code and Mitigated code.

## `JAVA`

### Vulnerable Code

```java
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import java.io.File;

public class VulnerableXMLProcessor {

    public static void main(String[] args) throws Exception {
        String uploadedFilePath = "/path/to/uploaded/file.xml"; // User-supplied path

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        // Assuming 'uploadedFilePath' is the path provided by the user
        File xmlFile = new File(uploadedFilePath);
        Document document = builder.parse(xmlFile);

        NodeList nodeList = document.getElementsByTagName("data");
        // Process the data...

        System.out.println("XML processing completed.");
    }
}
```

The above code is Vulnerable since the application takes a `file path` provided by the user and directly attempts to parse it as an XML document. If an attacker uploads a `malicious XML file` with external entity references, they might be able to perform XXE attacks, potentially leading to information disclosure or other security risks.

* Some of the ways the vulnerable code can be mitigated is:
  1. **Disable External Entity Processing**:
     *   Configure the XML parser to disable the processing of external entities. This can be done by setting the appropriate features. For example:

         ```java

         factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
         ```
  2. **Use Secure Parsers**:
     * Consider using secure XML parsing libraries that have built-in protections against XXE attacks. Libraries like OWASP's **`ESAPI`** or secure XML parsers provided by trusted sources can be more robust.
  3. **Validate User Input**:
     * Always validate user input before processing it as XML. Ensure that the XML data comes from a trusted and expected source.
  4. **Avoid Using DTDs**:
     * If possible, avoid using Document Type Definitions (DTDs) in your XML documents. If you must use them, ensure that they do not contain references to external entities.
  5. **Restrict File Access**:
     * If the application reads XML data from files, ensure that it only reads from trusted and controlled locations. Avoid using user-provided file paths without proper validation.
  6. **Sanitize Input for Web Applications**:
     * For web applications, ensure that any XML data submitted by users is properly sanitized and validated before processing. Implement input validation and filtering to remove any potentially dangerous content.

### Mitigated Code

```java
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import java.io.File;

public class SecureXMLProcessor {

    public static void main(String[] args) throws Exception {
        String uploadedFilePath = "/path/to/uploaded/file.xml"; // User-supplied path

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        DocumentBuilder builder = factory.newDocumentBuilder();

        // Assuming 'uploadedFilePath' is the path provided by the user
        File xmlFile = new File(uploadedFilePath);
        Document document = builder.parse(xmlFile);

        NodeList nodeList = document.getElementsByTagName("data");
        // Process the data...

        System.out.println("XML processing completed.");
    }
}
```

* The Mitigated code does the following:
  1. **Disallowing DTD Declarations**: This is achieved with the line **`factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`**. This prevents the XML parser from processing any DTD declarations, which can be used in XXE attacks.
  2. **Disabling External General Entities**: The line **`factory.setFeature("http://xml.org/sax/features/external-general-entities", false);`** disables the processing of external general entities. These entities could potentially reference external resources, making them a vector for XXE attacks.
  3. **Disabling External Parameter Entities**: The line **`factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);`** disables the processing of external parameter entities. Similar to external general entities, these can also be used in XXE attacks.
  4. **Disabling `XInclude Processing`**: The line **`factory.setXIncludeAware(false);`** disables `XInclude processing`. This is important because XInclude can also introduce potential XXE vulnerabilities.
  5. **Disabling Entity Expansion**: The line **`factory.setExpandEntityReferences(false);`** ensures that entity references are not expanded. This is another important measure to prevent XXE attacks.

## `PHP`

### Vulnerable Code

```php
<?php
// Get user-provided XML data from a form submission
$userInput = $_POST['xml_data'];

// Process the user-supplied XML
$dom = new DOMDocument;
$dom->loadXML($userInput);

// Extract and display data from the XML
$names = $dom->getElementsByTagName('name');
foreach ($names as $name) {
    echo "Name: " . $name->nodeValue . "<br>";
}
?>
```

In this code, the application directly loads and processes XML data provided by the user `without proper validation`. If an attacker submits `malicious XML data with external entity references`, they can potentially launch XXE attacks, which may lead to information disclosure or other security issues.

*   Some of the ways the Vulnerable code can be mitigated is: \*\*`Disable External Entity Processing**:`Configure the XML parser to disable the processing of external entities:

    ```php
    libxml_disable_entity_loader(true);
    ```

    * \*\*`Validate and Sanitize User Input**:` Implement strict validation checks on user-supplied XML data to ensure it adheres to expected formats. Remove or reject any suspicious or unnecessary content.
    * \*\*`Use Safe Parsers**:` Consider using safe XML parsing libraries or functions that have built-in protections against XXE attacks.
    * \*\*`Limit Access to Resources**:` Ensure that the web application has limited access to sensitive resources on the server, even if XXE attacks are successful.

### Mitigated Code

```php
<?php
// Get user-provided XML data from a form submission
$userInput = $_POST['xml_data'];

// Create a new DOMDocument instance
$dom = new DOMDocument;

// Disable the loading of external entities
libxml_disable_entity_loader(true);

// Load the user-supplied XML with options to prevent XXE attacks
$loadOptions = LIBXML_DTDLOAD | LIBXML_NOENT | LIBXML_NONET;
$dom->loadXML($userInput, $loadOptions);

// Extract and display data from the XML
$names = $dom->getElementsByTagName('name');
foreach ($names as $name) {
    // Use htmlspecialchars to prevent XSS attacks
    echo "Name: " . htmlspecialchars($name->nodeValue, ENT_QUOTES, 'UTF-8') . "<br>";
}
?>
```

*   The Mitigated code does the following:

    * **Disabling External Entities (XXE Mitigation)**:

    ```php
    libxml_disable_entity_loader(true);
    ```

    This function disables the loading of external entities, which is crucial for preventing XXE attacks.

    **Load XML with Specific Options (XXE Mitigation)**:

    ```php
    $loadOptions = LIBXML_DTDLOAD | LIBXML_NOENT | LIBXML_NONET;
    $dom->loadXML($userInput, $loadOptions);
    ```

    These options prevent various forms of XXE attacks:

    * **`LIBXML_DTDLOAD`** ensures that DTDs are not loaded.
    * **`LIBXML_NOENT`** prevents the expansion of entities.
    * **`LIBXML_NONET`** disables network access.

    **Preventing XSS Attacks**:

```php
echo "Name: " . htmlspecialchars($name->nodeValue, ENT_QUOTES, 'UTF-8') . "<br>";
```

This line uses **`htmlspecialchars`** to encode special characters in the **`nodeValue`** of the **`<name>`** element. This helps prevent Cross-Site Scripting (XSS) attacks by ensuring that any HTML characters are displayed as text.

## `Ruby`

### Vulnerable Code

```php
require 'rexml/document'

def process_xml(xml_data)
  doc = REXML::Document.new(xml_data)
  content = doc.root.text
  puts "Content: #{content}"
end

user_input = gets.chomp

# Assume user_input contains XML data fetched from an untrusted source
process_xml(user_input)
```

In this code, the application processes XML data from the user without properly sanitizing or validating it. If an attacker provides malicious XML with external entity references, it could lead to an XXE attack.

* Some of the ways the Vulnerable code can be mitigated is:
  * \*\*`Disable External Entity Processing**:` Configure the XML parser to disable the processing of external entities. In Ruby's REXML, this is not a direct feature, but you can implement it manually using other techniques.
  * \*\*`Use Secure XML Parsers**:` Consider using more secure XML parsing libraries or gems that have built-in protections against XXE attacks. For example, **`Nokogiri`** with proper configuration is a popular choice.
  * \*\*`Validate and Sanitize XML Data**:` Implement strict validation and sanitization checks on XML data from untrusted sources before processing it.
  * **`Limit File Access`**: If your application processes XML files, ensure that it only reads from trusted and controlled locations, and doesn't allow access to sensitive files.
  * \*\*`Regularly Monitor XML Data Sources**:` Keep an eye on the sources of XML data and monitor for any unusual or unexpected behavior.

### Mitigated Code

```php
require 'rexml/document'

def process_xml(xml_data)
  # Create a new REXML::Parsers::SAX2Parser
  parser = REXML::Parsers::SAX2Parser.new(xml_data)

  # Disable the expansion of entities
  parser.entity_expansion_text_limit = 0

  # Parse the XML and get the root element
  doc = REXML::Document.new
  parser.parse(doc)
  content = doc.root.text

  puts "Content: #{content}"
end

user_input = gets.chomp

# Assume user_input contains XML data fetched from an untrusted source
process_xml(user_input)
```

*   The Mitigated code does the following:

    * \*\*`Disabling Entity Expansion**:`

    ```ruby
    parser.entity_expansion_text_limit = 0
    ```

    This line sets the entity expansion text limit to zero, effectively disabling the expansion of entities. This is a crucial step in preventing XXE attacks.

    *   \*\*`Using REXML's SAX2Parser**:`

        ```php
        parser = REXML::Parsers::SAX2Parser.new(xml_data)
        ```

        The use of REXML's SAX2Parser indicates that the code is handling the XML data in a way that is more resilient against XXE attacks compared to other parsers.
    *   \*\*`Parsing XML with REXML**:`

        ```xml
        parser.parse(doc)
        ```

        The XML is parsed using REXML, which is a widely-used and well-maintained library. REXML is designed to be secure and robust.
    *   **User Input Handling**:

        ```makefile
        user_input = gets.chomp
        ```

        The code prompts the user for input, which suggests that the XML data is expected to be provided interactively. This can be a safer approach compared to directly accepting untrusted input from external sources.

## Mitigation

* Some Common Mitigation techniques include:
  * \*\*`Disable Entity Expansion**:` Disable the expansion of entities in the XML parser settings. This prevents the parser from resolving external entities.
  * \*\*`Use a Safe Parser**:` Choose a secure XML parser or library that explicitly provides protection against XXE attacks. Some parsers have built-in features or options to mitigate XXE vulnerabilities.
  * \*\*`Validate and Sanitize Input**:` Validate and sanitize any XML data received from untrusted sources. Ensure it adheres to the expected XML structure before processing it.
  * \*\*`Disallow DTDs**:` If possible, configure the parser to disallow Document Type Definitions (DTDs) or to ignore them entirely. DTDs are a common vector for XXE attacks.
  * \*\*`Disable External Entity Loading**:` Configure the parser to disable the loading of external entities. This prevents the parser from fetching resources from external sources.
  * \*\*`Use Whitelists (if applicable)**:` Define a whitelist of allowed elements, attributes, and entities in your XML schema. Enforce this whitelist during validation.
  * \*\*`Implement Input Validation**:` Apply strict input validation to ensure that user-supplied data adheres to expected formats and structures. Reject any input that does not meet these criteria.
  * \*\*`Sanitize Output (if necessary)**:` If the XML data is being used in an HTML context, use proper output encoding techniques (like HTML escaping) to prevent Cross-Site Scripting (XSS) attacks.
  * \*\*`Avoid Dynamic External References**:`Avoid using dynamic or user-controlled input in references to external resources (e.g., file paths, URLs) within the XML.

## References

{% embed url="https://cwe.mitre.org/data/definitions/611.html" %}

[What is XXE (XML external entity) injection? Tutorial & Examples | Web Security Academy](https://portswigger.net/web-security/xxe)

[XML External Entity Prevention - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/XML\_External\_Entity\_Prevention\_Cheat\_Sheet.html)

[XXE Complete Guide: Impact, Examples, and Prevention | HackerOne](https://www.hackerone.com/knowledge-center/xxe-complete-guide-impact-examples-and-prevention)
