package net.ripe.db.whois.update.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;

/**
 * Created by michel on 5/9/14.
 */
@Component
public class SubAllocationWindowRESTCaller {
    private static final Logger LOGGER = LoggerFactory.getLogger(SubAllocationWindowRESTCaller.class);
    private static final String ORG_HANDLE = "org_handle";
    private static final String SAW = "saw";
    private static final String SAW_V4 = "saw_v4";
    private static final String SAW_V6 = "saw_v6";

    private String url = null;
    private HttpConnexionUtils httpConnexionUtils;

    @Autowired
    public SubAllocationWindowRESTCaller(final HttpConnexionUtils httpConnexionUtils) {
        this.httpConnexionUtils = httpConnexionUtils;
    }

    @Value("${whois.saw.rest.url}")
    public void setUrl(final String sawRestUrl) {
        this.url = sawRestUrl;

        if (this.url != null & !this.url.endsWith("/")) {
            this.url += "/";
        }
        LOGGER.info("SAW REST URL : ", this.url);
    }

    public Integer getSAW4(final String orgHdl) {
        String xmlResponse = httpConnexionUtils.executeGet(url + orgHdl);
        return (xmlResponse != null) ? extractSAW4(xmlResponse) : null;
    }

    private Integer extractSAW4(String xml) {
        return extractSAW(xml, SAW_V4);
    }

    public Integer getSAW6(final String orgHdl) {
        String xmlResponse = httpConnexionUtils.executeGet(url + orgHdl);
        return (xmlResponse != null) ? extractSAW6(xmlResponse) : null;
    }

    private Integer extractSAW6(String xml) {
        return extractSAW(xml, SAW_V6);
    }

    private Integer extractSAW(String xml, String sawTag) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(xml));
            Document document = builder.parse(is);

            // root
            Element customer = document.getDocumentElement();
            Node orgHandleNode = customer.getElementsByTagName(ORG_HANDLE).item(0);
            String orgHandle = orgHandleNode.getTextContent();

            if (orgHandle == null || "".equals(orgHandle)) {
                return null;
            }

            Node saw = customer.getElementsByTagName(SAW).item(0);

            NodeList nodeList = saw.getChildNodes();
            int nodeListLength = nodeList.getLength();

            for (int i = 0; i < nodeListLength; i++) {
                Node n = nodeList.item(i);
                if (n.getNodeName().equals(sawTag)) {
                    return Integer.valueOf(n.getTextContent());
                }
            }
        } catch (Exception e) {
            LOGGER.error(e.toString());
        }
        return null;
    }
}
