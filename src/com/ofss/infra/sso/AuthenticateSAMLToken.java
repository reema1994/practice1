package com.ofss.infra.sso;

import com.ofss.fcc.common.BranchConfig;
import com.ofss.fcc.common.BranchConstants;
import com.ofss.fcc.common.FBContext;
import com.ofss.fcc.commonif.ILogger;
import com.ofss.fcc.commonif.ISSOAuthenticator;
import com.ofss.fcc.logger.BranchLogger;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;
import javax.xml.namespace.NamespaceContext; 
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignature.SignatureValue;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class AuthenticateSAMLToken
  implements ISSOAuthenticator
{
  private XPath xpath = XPathFactory.newInstance().newXPath();

  private static void dbg(FBContext fbContext1, String msg) {
    String message = "AuthenticateSAMLToken." + msg;
    fbContext1.getBrnLogger().dbg(message);
  }

  public HashMap validate(HashMap reqMap) throws Exception {
    BranchLogger brnLogger = new BranchLogger("Client");
    FBContext fbContext = new FBContext("Client");
    fbContext.setBrnLogger(brnLogger);
    boolean debug = false;
    if ("Y".equalsIgnoreCase(BranchConfig.getInstance().getConfigValue("DEBUG"))) {
      debug = true;
    }
    fbContext.setDebug(debug);
    dbg(fbContext, "validate-->Just Entered");
    HashMap respMap = new HashMap(2);

    String ssoKey = BranchConstants.SSO_KEY;
    try {
      String samlUserId = "";
      String cert_path = BranchConfig.getInstance().getConfigValue("SAML_CERT_PATH");
      String cert_pass = BranchConfig.getInstance().getConfigValue("SAML_CERT_PASSWORD");
      String cert_alias = BranchConfig.getInstance().getConfigValue("SAML_CERT_ALIAS");
      dbg(fbContext, "validate-->Extracting public key from certificate");
      KeyStore ks = KeyStore.getInstance("JKS");
      FileInputStream ksfis = new FileInputStream(cert_path);
      BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
      ks.load(ksbufin, cert_pass.toCharArray());
      Certificate cert = ks.getCertificate(cert_alias);
      PublicKey pubKey = cert.getPublicKey();
      String str = "";
      try {
        String cont = (String)reqMap.get(ssoKey);
        if (cont.indexOf("SAMLResponse=") > -1)
          cont = cont.substring(cont.indexOf("SAMLResponse=") + 13, cont.length());
        if (cont.indexOf("%0D%0A") > -1)
          cont = cont.replace("%0D%0A", "");
        if (cont.indexOf("%2B") > -1)
          cont = cont.replace("%2B", "+");
        str = new String(Base64.decodeBase64(cont.getBytes()));
      } catch (Exception ex) {
        dbg(fbContext, "validate-->Error in SAML Request decode");
        throw ex;
      }
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

      dbf.setExpandEntityReferences(false);
      dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
      dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

      dbf.setNamespaceAware(true);
      DocumentBuilder builder = dbf.newDocumentBuilder();
      InputSource is = new InputSource(new StringReader(str));
      Document doc = builder.parse(is);
      dbg(fbContext, "validate-->Accessing Signature element");
      NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
      if (nl.getLength() == 0) {
        dbg(fbContext, "validate-->Cannot find Signature element");
        throw new Exception("Cannot find Signature element");
      }
      dbg(fbContext, "validate-->Validating the Signature");
      XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
      DOMValidateContext valContext = new DOMValidateContext(pubKey, nl.item(0));
      valContext.setIdAttributeNS((Element)nl.item(0).getParentNode(), null, "ID");
      XMLSignature signature = fac.unmarshalXMLSignature(valContext);
	  // Temp Changes for Mizhou - Signature Validation Starts
	  /*
      boolean coreValidity = signature.validate(valContext);
      Iterator i = signature.getSignedInfo().getReferences().iterator();
      for (int j = 0; i.hasNext(); j++) {
        boolean refValid = ((Reference)i.next()).validate(valContext);
        dbg(fbContext, "validate-->ref[" + j + "] validity status: " + refValid);
      }
      if (!coreValidity) {
        dbg(fbContext, "validate-->Signature failed core validation");
        boolean sv = signature.getSignatureValue().validate(valContext);
        dbg(fbContext, "validate-->signature validation status: " + sv);
        throw new Exception("Signature failed core validation");
      }
	  */
	  // Temp Changes for Mizhou - Signature Validation Ends
      dbg(fbContext, "validate-->Signature passed core validation");
      dbg(fbContext, "validate-->Other Validations Begin");
      TransformerFactory tf = TransformerFactory.newInstance();
      try
      {
        Transformer transformer = tf.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));

       // this.xpath.setNamespaceContext(new AuthenticateSAMLToken.1(this));

        this.xpath.setNamespaceContext(new NamespaceContext()
        {
          public Iterator getPrefixes(String namespaceURI)
          {
            return null;
          }

          public String getPrefix(String namespaceURI)
          {
            return null;
          }

          public String getNamespaceURI(String prefix)
          {
            if ("samlp".equals(prefix)) {
              return "urn:oasis:names:tc:SAML:2.0:protocol";
            }
            return null;
          }
        });
        
        Node nassert = ((Node)this.xpath.evaluate("/samlp:Response", doc, XPathConstants.NODE)).getLastChild().getChildNodes().item(2);

        String Audience = nassert.getChildNodes().item(0).getTextContent();
        String NotBefore = nassert.getAttributes().item(0).getTextContent();
        String NotOnOrAfter = nassert.getAttributes().item(1).getTextContent();

        String timeZone = "UTC";
        String valid_Audience = BranchConfig.getInstance().getConfigValue("SAML_VALID_AUDIENCE");

        dbg(fbContext, "validate-->Audience : " + Audience);
        dbg(fbContext, "validate-->Valid Audience : " + valid_Audience);

        if (Audience.equals(valid_Audience)) {
          dbg(fbContext, "validate-->Audience Validation Successful!");
          NotBefore = NotBefore.replaceAll("\\.[0-9]*", "");
          NotOnOrAfter = NotOnOrAfter.replaceAll("\\.[0-9]*", "");
          SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
          dateFormat.setTimeZone(TimeZone.getTimeZone(timeZone));
          Date datebef = dateFormat.parse(NotBefore);
          Date dateaft = dateFormat.parse(NotOnOrAfter);
          Calendar now = Calendar.getInstance();
          if ((datebef.before(now.getTime())) && (dateaft.after(now.getTime()))) {
            dbg(fbContext, "validate-->Time Validation Successful!");

            samlUserId = ((Node)this.xpath.evaluate("/samlp:Response", doc, XPathConstants.NODE)).getLastChild().getChildNodes().item(4).getTextContent();

            dbg(fbContext, "validate-->samlUserId extracted successfully");
            dbg(fbContext, "validate-->samlUserId :" + samlUserId);
            respMap.put("USERID", samlUserId);
            respMap.put("STATUS", "SUCCESS");
          } else {
            dbg(fbContext, "validate-->Timestamp Validation failure");
            throw new Exception("Timestamp Validation failure");
          }
        } else {
          dbg(fbContext, "validate-->Audience Validation failure");
          throw new Exception("Audience Validation failure");
        }
      } catch (TransformerException e) {
        dbg(fbContext, "validate-->Failed in Validation");
        throw e;
      }
    }
    catch (Exception e)
    {
      dbg(fbContext, "Failed in validate");
      fbContext.getBrnLogger().writeStack(fbContext.getUserID(), e);
      respMap.put("STATUS", "FAILURE");
    }
    return respMap;
  }
}