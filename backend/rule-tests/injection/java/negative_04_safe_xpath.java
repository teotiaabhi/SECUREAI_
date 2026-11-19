// Test: negative for rule JAVA-INJ-004
// Expected: should_not_trigger
// Category: injection
// Language: java

package com.acme.secure.service;

import org.springframework.stereotype.Service;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class ProductCatalogService {

    private static final String CATALOG_XML = "/var/app/data/product-catalog.xml";

    /**
     * Searches the XML product catalog by product name.
     * This method is safe because it uses XPathVariableResolver to bind
     * user input as a variable rather than concatenating it into the
     * XPath expression string, preventing XPath injection.
     *
     * @param productName the product name received from the HTTP request parameter
     * @return list of matching product descriptions
     */
    public List<String> searchProducts(String productName) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new File(CATALOG_XML));

        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath = xPathFactory.newXPath();

        // SAFE: User input bound through XPathVariableResolver, not concatenation
        xpath.setXPathVariableResolver(new XPathVariableResolver() {
            @Override
            public Object resolveVariable(QName variableName) {
                if ("productName".equals(variableName.getLocalPart())) {
                    return productName;
                }
                return null;
            }
        });

        String expression = "//products/product[name=$productName]/description";
        XPathExpression xPathExpr = xpath.compile(expression);

        NodeList nodeList = (NodeList) xPathExpr.evaluate(document, XPathConstants.NODESET);

        List<String> descriptions = new ArrayList<>();
        for (int i = 0; i < nodeList.getLength(); i++) {
            descriptions.add(nodeList.item(i).getTextContent());
        }

        return descriptions;
    }
}
