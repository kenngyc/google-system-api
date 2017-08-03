package com.knyc.demo;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.util.encoders.Base64;
import org.mule.api.MuleEventContext;
import org.mule.api.lifecycle.Callable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.*;
import java.util.Date;

public class GenerateJwtToken implements Callable{
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	@Override
	public String onCall(MuleEventContext eventContext) throws Exception {

		//Get the required Google JWT properties.
		String issuer = eventContext.getMuleContext().getRegistry().get("googleJWT.issuer");
		String scope = eventContext.getMuleContext().getRegistry().get("googleJWT.scope");
	    String subject = eventContext.getMuleContext().getRegistry().get("googleJWT.subject");
	    String audience = eventContext.getMuleContext().getRegistry().get("googleJWT.audience");
	    String ttlMsStr = eventContext.getMuleContext().getRegistry().get("googleJWT.ttlMs");
	    
	    logger.debug("GoogleJWT.issuer={}",issuer);
		logger.debug("GoogleJWT.scope={}",scope);
		logger.debug("GoogleJWT.subject={}",subject);
		logger.debug("GoogleJWT.audience={}",audience);
		logger.debug("GoogleJWT.ttlMs={}",ttlMsStr);
	
		RSAPrivateKey prikey = null;
		try {
			//Load the gsuite,key used to sign the token
			ClassLoader classLoader = getClass().getClassLoader();
		    URL gsuiteKeyResource = classLoader.getResource("gsuite.key");
			
	        File filePrivateKey = new File(gsuiteKeyResource.getFile());
	        FileInputStream fis = new FileInputStream(gsuiteKeyResource.getFile());
	        
	        byte[] privateKey = new byte[(int) filePrivateKey.length()];
	        fis.read(privateKey);
	        fis.close();
	        
	        byte[] encoded = Base64.decode(privateKey);

	        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
	        PKCS8EncodedKeySpec privatekeySpec = new PKCS8EncodedKeySpec(encoded);
	        prikey = (RSAPrivateKey) keyFactory.generatePrivate(privatekeySpec);
		
			//The JWT signature algorithm we will be using to sign the token
		    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
		    long nowMs = System.currentTimeMillis();
		    long expMs = nowMs + Long.parseLong(ttlMsStr);
		    Date now = new Date(nowMs);
	        Date exp = new Date(expMs);
		  
		    //Let's set the JWT Claims
		    JwtBuilder builder = Jwts.builder()
		                                .setIssuedAt(now)
		                                .setSubject(subject)
		                                .setIssuer(issuer)
		                                .setAudience(audience)
		                                .claim("scope",scope)
		                                .signWith(signatureAlgorithm, prikey)
		        						.setExpiration(exp);
		 
		    //Builds the JWT and serializes it to a compact, URL-safe string
		    return builder.compact();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return "";
	    }
	}
}
