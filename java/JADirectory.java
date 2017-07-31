
import java.io.UnsupportedEncodingException;
import java.util.Hashtable;
import java.util.Properties;

// Active Directory
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
*	Java for Active Directory, can create users, modify passwords, check credentials, get user information, check if login exists.
*	@author Guille Rodriguez - http://www.github.com/guillerg86
*	
*/
public class JADirectory {
		
	public static final String BASEDN_DEFAULT			= "OU=MyOU,DC=subdomain,DC=domain,DC=com";
	public static final String BASEDN_STAFF 			= "OU=Staff,DC=subdomain,DC=domain,DC=com";

	
	public static final String CLASS_VERSION 			= "1.2017.07.28";				
	public static final String CLASS_NAME				= "JADirectory v"+CLASS_VERSION;
	
	public static final String 	LDAPCTXFACTORY 			= "com.sun.jndi.ldap.LdapCtxFactory";
    public static final int 	AD_LDAP_PORT     		= 389;
    public static final int 	AD_LDAPS_PORT    		= 636;
    public static final String 	AD_LDAP_PREFIX   		= "ldap://";
    public static final String 	AD_LDAPS_PREFIX  		= "ldaps://";
    public static final String 	AD_LDAP_VERSION  		= "3";
    
	// USER FIELDS
	public static final String USERFIELD_ID				= "objectSid";		
	public static final String USERFIELD_EMAIL 			= "mail";
	public static final String USERFIELD_LOGIN 			= "samaccountname";
	public static final String USERFIELD_CNNAME			= "cn";
	public static final String USERFIELD_NAME 			= "givenname";
	public static final String USERFIELD_UPDPASSWORD	= "unicodePwd";
	public static final String USERFIELD_DISTINGNAME	= "distinguishedname";
	public static final String USERFIELD_VISIBLEPASS  	= "userpassword";
	public static final String USERFIELD_SURNAME		= "sn";
	public static final String USERFIELD_PASSWORD		= "unicodePwd";
	public static final String USERFIELD_DISPLAYNAME	= "displayname";
	public static final String USERFIELD_DESCRIPTION	= "description";
	public static final String USERFIELD_PROXYADDRESSES = "proxyaddresses";
	public static final String USERFIELD_EMPLOYEETYPE 	= "employeetype";
	public static final String USERFIELD_INFO 			= "info";
	
	public static final int 	USERFIELD_LOGIN_MAXSIZE = 20;
	
	
	// CONNECTION DATA
	private boolean secured = false;
	private String base									= BASEDN_DEFAULT;
	private String domain 								= "adserver.domain.com";
	private String user									= "userWithGrants";
	private String pass									= "passwordForUser";
	private String srvAD1 								= "adserver1.domain.com";
	private String srvAD2 								= "adserver2.domain.com";
	private static final String passregex				= "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$";	// Minimun 8 characters ( 1 Mayus, 1 Minus, 1 Number)

	private LdapContext connection;
	private SearchControls searchCtls;
	
	public JADirectory(){
		this.searchCtls = new SearchControls();
		this.searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
	}
	/**
	 * Creates a object with paratemeters given
	 * @param domain Domain of ADirectory
	 * @param user User with grants
	 * @param pass Password for the user
	 * @param server1 IP or Domain of server 1
	 * @param server2 IP or Domain of server 2
	 * @param basedn Branch of the user with grants (BASEDN)
	 * @return JADirectory-Object
	 */
	public static JADirectory JADirectoryWithParams(String domain, String user, String pass, String server1, String server2, String basedn) {
		JADirectory adConnection = new JADirectory();
		adConnection.setDomain(domain);
		adConnection.setUser(user);
		adConnection.setPass(pass);
		adConnection.setServer1(server1);
		adConnection.setServer2(server2);
		adConnection.setBase(basedn);
		return adConnection;
	}
	/**
	 * Creates a object with parameters inside Properties object
	 * @param propsAD Properties object Key-Value
	 * @return JADirectory-Object
	 */
	public static JADirectory JADirectoryWithProperties(Properties propsAD) {
		String ad_secured_str = propsAD.getProperty("adirectory_secured");
		
		JADirectory adConnection = new JADirectory();
		adConnection.setDomain(propsAD.getProperty("adirectory_domain"));
		adConnection.setUser(propsAD.getProperty("adirectory_user"));
		adConnection.setPass(propsAD.getProperty("adirectory_pass"));
		adConnection.setBase(propsAD.getProperty("adirectory_defaultbasedn"));
		adConnection.setServer1(propsAD.getProperty("adirectory_server1"));
		adConnection.setServer2(propsAD.getProperty("adirectory_server2"));
		if ( ad_secured_str.equalsIgnoreCase("S") || ad_secured_str.equalsIgnoreCase("Y") ) {
			adConnection.enableSecureConnection();
		}		
		return adConnection;
	}
	
	
	/**
	*	Allows the user to activate secure connection. Must be configured before running a connect if you want to secure the connection.
	*	Also, needs the certificate.cer of the ADirectory Server
	*/
	public void enableSecureConnection() {
		this.secured = true;
		// Readding certificate from keyStore
		Properties sysProps = new Properties(System.getProperties());
		String keystore = sysProps.getProperty("java.home")+"/lib/security/cacerts";
		System.setProperty("javax.net.ssl.trustStore",keystore);
		System.setProperty("javax.net.ssl.trustStorePassword","changeit");	
	}
	
	/**
	*	Allows the user to deactivate secure connection. In this mode you can't create a user or modify user password.
	*/
	public void disableSecureConnection() {
		this.secured = false;
	}
	
	
	/**
	* If isn't connected, try to connect to Server1 and if fails, try to connect to Server2 
	*/
	public boolean connect() throws Exception{
		//	StartTlsResponse tls = null;
		if ( this.isConnected() == false ) {
			Hashtable<String,String> env = new Hashtable<String,String>();
			env.put(Context.INITIAL_CONTEXT_FACTORY, LDAPCTXFACTORY );
			if ( this.secured ) {
				env.put(Context.PROVIDER_URL, AD_LDAPS_PREFIX+srvAD1+":"+AD_LDAPS_PORT);
				env.put(Context.SECURITY_PROTOCOL,"ssl");
			} else {
				env.put(Context.PROVIDER_URL, AD_LDAP_PREFIX+srvAD1+":"+AD_LDAP_PORT);
			}
			env.put(Context.SECURITY_AUTHENTICATION, "simple");
			env.put(Context.SECURITY_PRINCIPAL, user+"@"+domain);
			env.put(Context.SECURITY_CREDENTIALS, pass);
			try {
				this.connection = new InitialLdapContext(env,null);
				return true;
			} catch (Exception e1) {
				try {
					if ( this.secured ) {
						env.put(Context.PROVIDER_URL, AD_LDAPS_PREFIX+srvAD2+":"+AD_LDAPS_PORT);
					} else {
						env.put(Context.PROVIDER_URL, AD_LDAP_PREFIX+srvAD2+":"+AD_LDAP_PORT);
					}
					this.connection = new InitialLdapContext(env,null);
					return true;
				} catch (Exception e2) {
					// Accion a tomar con la excepcion (enviar email??)
					return false;
				}
			}
		} else {
			return true;
		}
	}
	
	/**
	* Checks if connection is still established 
	*/
	public boolean isConnected() {
		if ( this.connection == null ) {
			return false;
		}
		return true;
	}
	
	/**
	* Close connection with ADirectory
	*/
	public void close() {
		try {
			if ( this.connection != null ) {
				this.connection.close();
				this.connection = null;
			}
		} catch (Exception e) {}
	}
	
	
	
/*--------------------------------------------------------------------------------------------------
 * READ QUERYS FOR ACTIVE DIRECTORY	
 *------------------------------------------------------------------------------------------------*/
	
    /**
     * Prepare filter for execute the Query
     * 
     * @param searchField Field we want to search
     * @param searchValue Value we want to search
     * @return String Returns the prepared filter
     */
	private String getFilter(String searchField, String searchValue) {
		String filter = "(&(objectClass=user)";
		
		if ( searchField.equalsIgnoreCase(USERFIELD_EMAIL) )  {
			filter +="("+USERFIELD_EMAIL+"="+ searchValue + ")";
		}
		
		if ( searchField.equalsIgnoreCase(USERFIELD_LOGIN) ) {
			filter +="("+USERFIELD_LOGIN+"="+searchValue+")"; 
		}
		if ( searchField.equalsIgnoreCase(USERFIELD_CNNAME) ) {
			filter +="("+USERFIELD_CNNAME+"="+searchValue+")"; 
		}		
		
		filter +=")";
		return filter; 
	}
    /**
     * Executes a query/search to Active Directory, called from another methods.
     * 
     * @param basedn BaseDN of Active Directory (OU,DC,DC) where we want to search.
     * @param filter The object type we want to search
     * @param fields Array with return fields (like SQL -> SELECT FIELD1, FIELD2, ... FROM TABLE)
     * @return NamingEnumeration Result of the query
     */
	private NamingEnumeration<SearchResult> execQuery(String basedn, String filter, String[] fields) throws NamingException, Exception {
		this.searchCtls.setReturningAttributes(fields);
		if ( !this.isConnected() ) {
			this.connect();
		}

		NamingEnumeration<SearchResult> result = null;
		if ( this.isConnected() ) {
			
			if ( basedn == null ) {
				basedn = this.base;
			}
			result = this.connection.search(basedn, filter, this.searchCtls);
		}
		return result;
	}
	
    /**
     * Converts the password string to "password" (with double) and then to  byte[] UTF-16LE
     * 
     * @param txtplainPass Contraseña en texto plano
     * @return byte[] Devuelve la contraseña en formato bytearray
     */
	public byte[] encodePassword(String txtplainPass) {
		String quotedPassword = "\""+txtplainPass+"\"";
		char unicodePwd[] = quotedPassword.toCharArray();
		byte[] pwdArray = null;

		try {
			pwdArray = quotedPassword.getBytes("UTF-16LE");
		} catch (UnsupportedEncodingException e) {}
		return pwdArray;
	}

    /**
     * Checks if login exists
     * 
     * @param login Login without domain we want to check
     * @param searchBase In what branch (BASEDN) we want to search 
     * @return boolean True --> If exists. False --> If not
     */
	public boolean existLogin(String login, String searchBase) throws Exception {
		String search = searchBase;
		if ( login.indexOf("*") != -1 ) {
			throw new Exception("No wildcard accepted!"); // Login matches, no wildcard accepted
		}
		String filter = this.getFilter(USERFIELD_LOGIN, login);
		String[] returningAttr = new String[] {	USERFIELD_LOGIN };
		
		if ( search == null ) { search = this.base; }
		NamingEnumeration<SearchResult> result = this.execQuery(search, filter, returningAttr);

		// If result != null && result.hasMore() -> then TRUE
		boolean exists = false;
		if ( result != null ) { exists = result.hasMore(); };
		return exists;
	}

	
    /**
     * Check if login and password are valid.
     * 
     * @param login Login of the user without domain.
     * @param password Password of the user
     * @param baseDN In what branch (BASEDN) we want to search 
     * @return boolean True --> If credentials are correct. False --> If not
     */	
	public boolean validateUserCredentials(String login, String password, String baseDN) throws Exception {
		// Search the user in this BASEDN
		String[] user = this.getUser(login, USERFIELD_CNNAME, baseDN);
		if (user == null) { 
			return false; 
		}
		
		String sec_principal = user[3];		// DistinguishedName
		
		// With CNNAME now lets try to connect
		Hashtable<String,String> env = new Hashtable<String,String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, LDAPCTXFACTORY );
		env.put(Context.PROVIDER_URL, AD_LDAP_PREFIX+this.srvAD1);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_CREDENTIALS, password);		
		env.put(Context.SECURITY_PRINCIPAL, sec_principal);

		LdapContext userConnection = null;
		// Let's try with server 1
		try {
			userConnection = new InitialLdapContext(env,null);
			return true;
		} catch (Exception e) {}
		
		// Let's try with server 2
		try {
			env.put(Context.PROVIDER_URL, AD_LDAP_PREFIX+this.srvAD2);
			userConnection = new InitialLdapContext(env,null);
			return true;
		} catch (Exception e) {
		}
		return false;
	}
	
	/**
	*	Checks if password matches validation regex
	*	@return True --> If matches. False --> If not
	*/
	public boolean isPasswordFormatValid(String password) {
		if ( password == null ) { return false; }
		return password.matches(passregex);
	}
		
	/**
	 * Gets user information
	 * <ul>
	 * <li>0 == Login</li>
	 * <li>1 == Name</li>
	 * <li>2 == CNName</li>
	 * <li>3 == DistinguishedName</li>
	 * <li>4 == Id</li>
	 * </ul>
	 * @param login Login of the user without domain.
	 * @param filterSearch Filter
	 * @param searchBase In what branch (BASEDN) we want to search 
	 * @return String[] --> If exists. Null --> If not exists 
	 * @throws NamingException
	 * @throws Exception
	 */
	public String[] getUser(String login, String filterSearch, String searchBase) throws NamingException, Exception {
		String[] user = null;
		String search = searchBase;

		String filter = this.getFilter(filterSearch, login);
		
		final String[] returningAttr = new String[] { 
			USERFIELD_ID,
			USERFIELD_LOGIN,
			USERFIELD_NAME,
			USERFIELD_CNNAME, 
			USERFIELD_DISTINGNAME
		};
		try {
			NamingEnumeration<SearchResult> result = null;
			if ( search == null ) { search = this.base; }
			result = this.execQuery(search,filter,returningAttr);
		
			if ( result.hasMore() ) {
				SearchResult row = result.next();
				Attributes attrs = row.getAttributes();
				user = this.loadFromCursor(row,attrs);
			}
		} catch (Exception e) {}
		
		return user;
	}

	/**
	 * Loads information of SearchResult "row" in a Array with user info
	 * @param cursor Row of the result
	 * @param attrs String[] with fields selected on Query
	 * @return String[] with data of the user
	 */
	protected String[] loadFromCursor(SearchResult cursor, Attributes attrs) {
		String[] user = new String[5];
		String nonParsedID		= attrs.get(USERFIELD_ID).toString().trim();
		String nonParsedLogin 	= attrs.get(USERFIELD_LOGIN).toString().trim();
		String nonParsedName	= attrs.get(USERFIELD_NAME).toString().trim();
		String nonParsedCn		= attrs.get(USERFIELD_CNNAME).toString().trim();
		String nonParsedDistn	= attrs.get(USERFIELD_DISTINGNAME).toString().trim();
		
		user[0] = nonParsedLogin.substring(nonParsedLogin.indexOf(":")+1).trim();
		user[1] = nonParsedName.substring(nonParsedName.indexOf(":")+1).trim();
		user[2] = nonParsedCn.substring(nonParsedCn.indexOf(":")+1).trim();
		user[3] = nonParsedDistn.substring(nonParsedDistn.indexOf(":")+1).trim();
		user[4] = nonParsedID.substring(nonParsedID.indexOf(":")+1).trim();
		return user;
	}
	
/*--------------------------------------------------------------------------------------------------
 * WRITE QUERYS FOR ACTIVE DIRECTORY	
 *------------------------------------------------------------------------------------------------*/

	/**
	 * Creates a user with login, password, basedn and aditional information
	 * @param login Login for the user (not existent <-- users checks before with {@link #existLogin(String, String)}) 
	 * @param password Password for the user
	 * @param baseDN Branch for the user (BASEDN)
	 * @param datos_adicionales Hashtable with adittional info, keys are USERFIELD_XXXXX
	 * @return True --> If created. False --> If not
	 * @throws Exception
	 */
	public boolean createUser(String login, String password, String baseDN, Hashtable<String,Object> datos_adicionales) throws Exception {
		// https://community.oracle.com/thread/1157499
		ModificationItem[] mods = new ModificationItem[2];
		
		int UF_ACCOUNTDISABLE 		= 0x0002;
		int UF_PASSWD_NOTREQD 		= 0x0020;
		int UF_PASSWD_CANT_CHANGE 	= 0x0040;
		int UF_NORMAL_ACCOUNT 		= 0x0200;
		int UF_DONT_EXPIRE_PASSWD 	= 0x10000;
		int UF_PASSWORD_EXPIRED 	= 0x800000;
		
		
		if ( baseDN == null ) { baseDN = this.base; }
		String usernameCN = "CN="+login+","+baseDN; 							
		try {
			Attributes attrs = new BasicAttributes(true);
			attrs.put("objectClass","user");
			attrs.put("samAccountName",login);									
			attrs.put("cn",login);		
			
			// More fields with info
			if ( datos_adicionales != null ) {
				String name 		= (String) datos_adicionales.get(USERFIELD_NAME);
				String displayname 	= (String) datos_adicionales.get(USERFIELD_DISPLAYNAME);
				String surname 		= (String) datos_adicionales.get(USERFIELD_SURNAME);
				String description 	= (String) datos_adicionales.get(USERFIELD_DESCRIPTION);
				String email 		= (String) datos_adicionales.get(USERFIELD_EMAIL);
				String employeetype = (String) datos_adicionales.get(USERFIELD_EMPLOYEETYPE);
				String info 		= (String) datos_adicionales.get(USERFIELD_INFO);
				
				if ( displayname != null ) { 
					attrs.put(USERFIELD_DISPLAYNAME, displayname); 				
				}
				if ( name != null ) { 
					attrs.put(USERFIELD_NAME, name);  							
				}
				if ( surname != null ) { 
					attrs.put(USERFIELD_SURNAME, surname); 						
				}
				if ( description != null ) { 
					attrs.put(USERFIELD_DESCRIPTION, description); 				
				}
				if ( email != null ) { 
					attrs.put(USERFIELD_EMAIL, email); 							
				}
				if ( employeetype != null )	{ 
					attrs.put(USERFIELD_EMPLOYEETYPE, employeetype); 			
				}
				if ( info != null && info.trim().length() > 0 ) {
					attrs.put(USERFIELD_INFO, info);
				}
			}

			// Need to configure user without password required (for now...) + disabled
			attrs.put("userAccountControl",Integer.toString(UF_NORMAL_ACCOUNT + UF_PASSWD_NOTREQD + UF_PASSWORD_EXPIRED + UF_ACCOUNTDISABLE));

			// Create user
			Context result = this.connection.createSubcontext(usernameCN, attrs);

			// Set password + configure as Normal Account + enable
			mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(USERFIELD_PASSWORD, this.encodePassword(password)  ) );
            mods[1] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userAccountControl",Integer.toString(UF_NORMAL_ACCOUNT)));
			this.connection.modifyAttributes(usernameCN, mods);

			// Set proxy addrs (can be more than 1)
			if ( datos_adicionales.get(USERFIELD_PROXYADDRESSES) != null ) {
				Object objTemp = datos_adicionales.get(USERFIELD_PROXYADDRESSES);
				if ( objTemp instanceof String[] ) {
					String[] proxyAddresses = (String[]) objTemp;
					int size = proxyAddresses.length;
					if ( size > 0 ) {
						ModificationItem[] modsProxyAddresses = new ModificationItem[size];
						for ( int i = 0; i<size; i++) {
							modsProxyAddresses[i] = new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute(USERFIELD_PROXYADDRESSES,""+proxyAddresses[i]));
						}
						this.connection.modifyAttributes(usernameCN, modsProxyAddresses);
					}
				}
			}
			return true;
		} catch (Exception e) {
			return false;	
		}
	}
	/**
	 * Change the password of the user if user exists
     * @param login Login of the user without domain.
     * @param password Password of the user
	 * @param searchBase In what branch (BASEDN) we want to search 
	 * @return True --> If password changed. False --> If not
	 * @throws Exception
	 */
	public boolean changeUserPassword(String login, String password, String searchBase) throws Exception{
		String[] user = null;
		String search = searchBase; if ( search == null ) { search = this.base; }
		if ( login.trim().length() == 0 ) {
			return false;
		}
		if ( password.trim().length() == 0 ) {
			return false;
		}
		boolean existLogin = this.existLogin(login,search);
		if ( existLogin ) {
			user = this.getUser(login,USERFIELD_LOGIN,search);

			try {
				ModificationItem[] mods = new ModificationItem[1];
				mods[0] = new ModificationItem( DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(USERFIELD_UPDPASSWORD, this.encodePassword(password)  ) );
				this.connection.modifyAttributes(user[3],mods);	// Using DistinguishedName for update
				return true;
			}catch (Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}
	
	/*
	 *	GETTERS AND SETTERS 
	 */
	public boolean isSecured() {
		return secured;
	}
	public String getBase() {
		return base;
	}
	public void setBase(String base) {
		this.base = base;
	}
	public String getDomain() {
		return domain;
	}
	public void setDomain(String domain) {
		this.domain = domain;
	}
	public void setUser(String user) {
		this.user = user;
	}
	public void setPass(String pass) {
		this.pass = pass;
	}
	public String getServer1() {
		return srvAD1;
	}
	public void setServer1(String srvAD1) {
		this.srvAD1 = srvAD1;
	}
	public String getServer2() {
		return srvAD2;
	}
	public void setServer2(String srvAD2) {
		this.srvAD2 = srvAD2;
	}

	
}