// Test: positive for rule JAVA-INJ-004
// Expected: should_trigger
// Category: injection
// Language: java

package com.acme.vulnerable.service;

import org.springframework.stereotype.Service;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class ProductCatalogServiceVuln {

    private static final String CATALOG_XML = "/var/app/data/product-catalog.xml";

    /**
     * Searches the XML product catalog by product name.
     * This method is vulnerable to XPath injection because user input is
     * concatenated directly into the XPath expression string without any
     * sanitization or parameterization.
     *
     * @param productName the product name received from the HTTP request parameter
     * @return list of matching product descriptions
     */
    public List<String> searchProducts(String productName) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new File(CATALOG_XML));

        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath = xPathFactory.newXPath();

        // VULNERABLE: User input concatenated directly into XPath expression
        String expression = "//products/product[name='" + productName + "']/description";
        XPathExpression xPathExpr = xpath.compile(expression);

        NodeList nodeList = (NodeList) xPathExpr.evaluate(document, XPathConstants.NODESET);

        List<String> descriptions = new ArrayList<>();
        for (int i = 0; i < nodeList.getLength(); i++) {
            descriptions.add(nodeList.item(i).getTextContent());
        }

        return descriptions;
    }
}
