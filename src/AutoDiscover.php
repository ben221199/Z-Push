<?php
/***********************************************
* File      :   autodiscover.php
* Project   :   Z-Push
* Descr     :   The autodiscover service for Z-Push.
*
* Created   :   14.05.2014
*
* Copyright 2007 - 2016 Zarafa Deutschland GmbH
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License, version 3,
* as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* Consult LICENSE file for details
************************************************/
namespace ZPush;

use Exception;
use SimpleXMLElement;
use Utils;
use ZPush\Lib\Core\ZLog;
use ZPush\Lib\Core\ZPush;
use ZPush\Lib\Core\ZPushDefs;
use ZPush\Lib\Exceptions\AuthenticationRequiredException;
use ZPush\Lib\Exceptions\FatalException;
use ZPush\Lib\Exceptions\FatalMisconfigurationException;
use ZPush\Lib\Exceptions\ZPushException;

class AutoDiscover{

	private static $instance;

	public const ACCEPTABLERESPONSESCHEMAMOBILESYNC = 'http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006';
	public const MAXINPUTSIZE = 8192; // Bytes, the autodiscover request shouldn't exceed that value

	private $config;

	public function __construct($CONFIG){
		$this->config = $CONFIG;
	}

	/**
	 * Static method to start the autodiscover process.
	 * @access public
	 * @param array $CONFIG
	 * @return void
	 * @throws ZPushException
	 */
    public static function doZPushAutoDiscover(array $CONFIG=[]): void{
        self::CheckConfig($CONFIG);
        ZLog::Write(LOGLEVEL_DEBUG, '-------- Start ZPushAutodiscover');
        ZLog::Write(LOGLEVEL_INFO, sprintf("Z-Push version='%s'", @constant('ZPUSH_VERSION')));
        // TODO use filterevilinput?
        if (!isset(self::$instance)) {
            self::$instance = new self($CONFIG);
        }
        if (stripos($_SERVER['REQUEST_METHOD'],'GET') !== false) {
            ZLog::Write(LOGLEVEL_INFO, 'ZPushAutodiscover::DoZPushAutodiscover(): GET request for autodiscover.');
            try {
                self::$instance->getLogin();
            }
            catch (Exception $ex) {
                if ($ex instanceof AuthenticationRequiredException) {
                    http_response_code(401);
                    header('WWW-Authenticate: Basic realm="ZPush"');
                }
            }
            if (!headers_sent()) {
                ZPush::PrintZPushLegal('GET not supported');
            }
            ZLog::Write(LOGLEVEL_DEBUG, '-------- End ZPushAutodiscover');
            exit(1);
        }

        self::$instance->DoAutodiscover();
        ZLog::Write(LOGLEVEL_DEBUG, '-------- End ZPushAutodiscover');
    }

    /**
     * Does the complete autodiscover.
     * @access public
     * @return void
     */
    public function DoAutodiscover(): void{
        $response = '';

        try {
            $incomingXml = $this->getIncomingXml();
            $backend = ZPush::GetBackend();
            $username = $this->login($backend, $incomingXml);
            $userDetails = $backend->GetUserDetails($username);
            $email = ($this->getAttribFromUserDetails($userDetails, 'emailaddress')) ?: $incomingXml->Request->EMailAddress;
            $userFullname = ($this->getAttribFromUserDetails($userDetails, 'fullname')) ?: $email;
            ZLog::Write(LOGLEVEL_WBXML, sprintf("Resolved user's '%s' fullname to '%s'", $username, $userFullname));
            $response = $this->createResponse($email, $userFullname);
            setcookie('membername', $username);
        } catch (Exception $ex) {
            // Extract any previous exception message for logging purpose.
            $exclass = get_class($ex);
            $exception_message = $ex->getMessage();
            if($ex->getPrevious()){
                do {
                    $current_exception = $ex->getPrevious();
                    $exception_message .= ' -> ' . $current_exception->getMessage();
                } while($current_exception->getPrevious());
            }

            ZLog::Write(LOGLEVEL_FATAL, sprintf('Exception: (%s) - %s', $exclass, $exception_message));

            if ($ex instanceof AuthenticationRequiredException) {
                if (isset($incomingXml)) {
                    // log the failed login attemt e.g. for fail2ban
                    if (isset($this->config['LOGAUTHFAIL']) && LOGAUTHFAIL != false)
                        ZLog::Write(LOGLEVEL_WARN, sprintf("Unable to complete autodiscover because login failed for user with email '%s' from IP %s.", $incomingXml->Request->EMailAddress, $_SERVER["REMOTE_ADDR"]));
                }
                else {
                    ZLog::Write(LOGLEVEL_ERROR, sprintf("Unable to complete autodiscover incorrect request: '%s'", $ex->getMessage()));
                }
                http_response_code(401);
                header('WWW-Authenticate: Basic realm="ZPush"');
            }
            else if ($ex instanceof ZPushException) {
                ZLog::Write(LOGLEVEL_ERROR, sprintf('Unable to complete autodiscover because of ZPushException. Error: %s', $ex->getMessage()));
                if(!headers_sent()) {
                    header('HTTP/1.1 '. $ex->getHTTPCodeString());
                    foreach ($ex->getHTTPHeaders() as $h) {
                        header($h);
                    }
                }
            }
        }

        $this->sendResponse($response);
    }

    /**
     * Processes the incoming XML request and parses it to a SimpleXMLElement.
     *
     * @access private
     * @throws ZPushException if the XML is invalid.
     * @throws AuthenticationRequiredException if no login data was sent.
     *
     * @return SimpleXMLElement
     */
    private function getIncomingXml(): SimpleXMLElement{
        if (isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] > self::MAXINPUTSIZE) {
            throw new ZPushException('The request will not be processed as the input exceeds our maximum expected input size.');
        }

        if (!isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
            throw new AuthenticationRequiredException();
        }

        $input = @file_get_contents('php://input', NULL, NULL, 0, self::MAXINPUTSIZE);
        if (strlen($input) === self::MAXINPUTSIZE) {
            throw new ZPushException('The request will not be processed as the input exceeds our maximum expected input size.');
        }

        $xml = simplexml_load_string($input);

        if (LOGLEVEL >= LOGLEVEL_WBXML) {
            ZLog::Write(LOGLEVEL_WBXML, sprintf('ZPushAutodiscover->getIncomingXml() incoming XML data:%s%s', PHP_EOL, $xml->asXML()));
        }

        if (!isset($xml->Request->EMailAddress)) {
            throw new FatalException('Invalid input XML: no email address.');
        }

        if (Utils::GetLocalPartFromEmail($xml->Request->EMailAddress) !== Utils::GetLocalPartFromEmail($_SERVER['PHP_AUTH_USER'])) {
            ZLog::Write(LOGLEVEL_WARN, sprintf("The local part of the server auth user is different from the local part in the XML request ('%s' != '%s')",
                Utils::GetLocalPartFromEmail($xml->Request->EMailAddress), Utils::GetLocalPartFromEmail($_SERVER['PHP_AUTH_USER'])));
        }

        if (!isset($xml->Request->AcceptableResponseSchema)) {
            throw new FatalException('Invalid input XML: no AcceptableResponseSchema.');
        }

        if (strcasecmp($xml->Request->AcceptableResponseSchema, self::ACCEPTABLERESPONSESCHEMAMOBILESYNC) !== 0) {
            throw new FatalException(sprintf('Request for a responseschema that is not supported (only mobilesync is supported): %s', $xml->Request->AcceptableResponseSchema));
        }

        return $xml;
    }

    /**
     * Logins using the backend's Logon function.
     *
     * @param IBackend $backend
     * @param String $incomingXml
     * @access private
     * @throws AuthenticationRequiredException if no login data was sent.
     *
     * @return string $username
     */
    private function login($backend, $incomingXml) {
        // don't even try to login if there is no PW set
        if (!isset($_SERVER['PHP_AUTH_PW'])) {
            throw new AuthenticationRequiredException("Access denied. No password provided.");
        }

        // Determine the login name depending on the configuration: complete email address or
        // the local part only.
        if (USE_FULLEMAIL_FOR_LOGIN) {
            $username = $incomingXml->Request->EMailAddress;
            ZLog::Write(LOGLEVEL_DEBUG, sprintf("ZPushAutodiscover->login(): Using the complete email address for login: '%s'", $username));
        }
        else {
            $username = Utils::GetLocalPartFromEmail($incomingXml->Request->EMailAddress);
            if (isset($this->config['AUTODISCOVER_LOGIN_TYPE']) && $this->config['AUTODISCOVER_LOGIN_TYPE'] !== ZPushDefs::AUTODISCOVER_LOGIN_EMAIL) {
                switch ($this->config['AUTODISCOVER_LOGIN_TYPE']) {
                    case ZPushDefs::AUTODISCOVER_LOGIN_NO_DOT:
                        $username = str_replace('.', '', $username);
                        break;
                    case ZPushDefs::AUTODISCOVER_LOGIN_F_NO_DOT_LAST:
                        $username = str_replace('.', '', substr_replace($username, '', 1, strpos($username, '.') - 1));
                        break;
                    case ZPushDefs::AUTODISCOVER_LOGIN_F_DOT_LAST:
                        $username = substr_replace($username, '', 1, strpos($username, '.') - 1);
                        break;
                }
                ZLog::Write(LOGLEVEL_DEBUG, sprintf('ZPushAutodiscover->login(): AUTODISCOVER_LOGIN_TYPE is set to %d', $this->config['AUTODISCOVER_LOGIN_TYPE']));
            }
            ZLog::Write(LOGLEVEL_DEBUG, sprintf('ZPushAutodiscover->login(): Using the username only for login: \'%s\'', $username));
        }

        // Mobile devices send Authorization header using UTF-8 charset. Outlook sends it using ISO-8859-1 encoding.
        // For the successful authentication the user and password must be UTF-8 encoded. Try to determine which
        // charset was sent by the client and convert it to UTF-8. See https://jira.z-hub.io/browse/ZP-864.
        $username = Utils::ConvertAuthorizationToUTF8($username);
        $password = Utils::ConvertAuthorizationToUTF8($_SERVER['PHP_AUTH_PW']);
        if ($backend->Logon($username, '', $password) === false) {
            throw new AuthenticationRequiredException('Access denied. Username or password incorrect.');
        }

        ZLog::Write(LOGLEVEL_DEBUG, sprintf("ZPushAutodiscover->login() successfull with '%s' as the username.", $username));
        return $username;
    }

    /**
     * Creates the XML response.
     *
     * @param string $email
     * @param string $userFullname
     * @access private
     *
     * @return string
     */
    private function createResponse($email, $userFullname): string{
        $xml = file_get_contents('response.xml');
        $zpushHost = $this->config['ZPUSH_HOST'] ?? $_SERVER['HTTP_HOST'] ?: $_SERVER['SERVER_NAME'];
        $serverUrl = 'https://' . $zpushHost . '/Microsoft-Server-ActiveSync';
        ZLog::Write(LOGLEVEL_INFO, sprintf('ZPushAutodiscover->createResponse(): server URL: \'%s\'', $serverUrl));
        $response = new SimpleXMLElement($xml);
        $response->Response->User->DisplayName = $userFullname;
        $response->Response->User->EMailAddress = $email;
        $response->Response->Action->Settings->Server->Url = $serverUrl;
        $response->Response->Action->Settings->Server->Name = $serverUrl;
        $response = $response->asXML();
        ZLog::Write(LOGLEVEL_WBXML, sprintf('ZPushAutodiscover->createResponse(): XML response:%s%s', PHP_EOL, $response));
        return $response;
    }

    /**
     * Sends the response to the device.
     * @param string $response
     * @access private
     *
     * @return void
     */
    private function sendResponse($response): void{
        ZLog::Write(LOGLEVEL_DEBUG, 'ZPushAutodiscover->sendResponse() sending response...');
        header('Content-type: text/html');
        $output = fopen('php://output', 'wb+');
        fwrite($output, $response);
        fclose($output);
        ZLog::Write(LOGLEVEL_DEBUG, 'ZPushAutodiscover->sendResponse() response sent.');
    }

    /**
     * Gets an attribute from user details.
     * @param array $userDetails
     * @param String $attrib
     * @access private
     *
     * @return string |false on error.
     */
    private function getAttribFromUserDetails($userDetails, $attrib){
        if (isset($userDetails[$attrib]) && $userDetails[$attrib]) {
            return $userDetails[$attrib];
        }
        ZLog::Write(LOGLEVEL_WARN, sprintf("The backend was not able to find attribute '%s' of the user. Fall back to the default value.", $attrib));
        return false;
    }

	/**
	 * Tries to login with the credentials from Auth header for GET requests.
	 *
	 * @access private
	 * @return void
	 * @throws AuthenticationRequiredException
	 */
    private function getLogin(): void{
        if (!isset($_SERVER['PHP_AUTH_PW'], $_SERVER['PHP_AUTH_USER'])) {
            throw new AuthenticationRequiredException('Access denied. No username or password provided.');
        }
        [$username,] = Utils::SplitDomainUser($_SERVER['PHP_AUTH_USER']);
        if(! USE_FULLEMAIL_FOR_LOGIN) {
            $username = Utils::GetLocalPartFromEmail($username);
        }
        $backend = ZPush::GetBackend();
        if ($backend->Logon($username,'', $_SERVER['PHP_AUTH_PW']) === false) {
            ZLog::Write(LOGLEVEL_ERROR, sprintf("ZPushAutodiscover->getLogin(): Login failed for user '%s' from IP %s.", $username, $_SERVER['REMOTE_ADDR']));
            throw new AuthenticationRequiredException('Access denied. Username or password incorrect.');
        }
    }

	/**
	 * @param $CONFIG
	 * @throws FatalMisconfigurationException
	 */
	public static function CheckConfig(&$CONFIG): void{
		if(!isset($CONFIG['REAL_BASE_PATH'])){
			$CONFIG['REAL_BASE_PATH'] = str_replace('autodiscover/','',$CONFIG['BASE_PATH']);
		}
		set_include_path(get_include_path().PATH_SEPARATOR.$CONFIG['REAL_BASE_PATH']);

		// set time zone
		// code contributed by Robert Scheck (rsc)
		if($CONFIG['TIMEZONE'] ?? false){
			if(!@date_default_timezone_set($CONFIG['TIMEZONE'])) {
				throw new FatalMisconfigurationException(sprintf("The configured TIMEZONE '%s' is not valid. Please check supported timezones at http://www.php.net/manual/en/timezones.php", constant('TIMEZONE')));
			}
		}
		else if(!ini_get('date.timezone')) {
			date_default_timezone_set('Europe/Amsterdam');
		}

		if (!isset($CONFIG['LOGBACKEND'])) {
			$CONFIG['LOGBACKEND'] = 'filelog';
		}

		if (strtolower($CONFIG['LOGBACKEND']) === 'syslog') {
			$CONFIG['LOGBACKEND_CLASS'] = 'Syslog';
			if (!isset($CONFIG['LOG_SYSLOG_FACILITY'])) {
				$CONFIG['LOG_SYSLOG_FACILITY'] = LOG_LOCAL0;
			}

			if (!isset($CONFIG['LOG_SYSLOG_HOST'])) {
				$CONFIG['LOG_SYSLOG_HOST'] = false;
			}

			if (!isset($CONFIG['LOG_SYSLOG_PORT'])) {
				$CONFIG['LOG_SYSLOG_PORT'] = 514;
			}

			if (!isset($CONFIG['LOG_SYSLOG_PROGRAM'])) {
				$CONFIG['LOG_SYSLOG_PROGRAM'] = 'z-push-autodiscover';
			}

			if (!is_numeric($CONFIG['LOG_SYSLOG_PORT'])) {
				throw new FatalMisconfigurationException('The LOG_SYSLOG_PORT must a be a number.');
			}

			if ($CONFIG['LOG_SYSLOG_HOST'] && $CONFIG['LOG_SYSLOG_PORT'] <= 0) {
				throw new FatalMisconfigurationException('LOG_SYSLOG_HOST is defined but the LOG_SYSLOG_PORT does not seem to be valid.');
			}
		}elseif (strtolower($CONFIG['LOGBACKEND']) === 'filelog') {
			$CONFIG['LOGBACKEND_CLASS'] = 'FileLog';

			if (!isset($CONFIG['LOGFILEDIR'])){
				throw new FatalMisconfigurationException('The LOGFILEDIR is not configured. Check if the config.php file is in place.');
			}

			if (substr($CONFIG['LOGFILEDIR'], -1,1) !== '/'){
				throw new FatalMisconfigurationException('The LOGFILEDIR should terminate with a \'/\'');
			}

			if (!file_exists($CONFIG['LOGFILEDIR'])){
				throw new FatalMisconfigurationException('The configured LOGFILEDIR does not exist or can not be accessed.');
			}

			if (!is_writable($CONFIG['LOGFILE']) || (!file_exists($CONFIG['LOGFILE']) && !touch($CONFIG['LOGFILE']))){
				throw new FatalMisconfigurationException('The configured LOGFILE can not be modified.');
			}

			if (!is_writable($CONFIG['LOGERRORFILE']) || (!file_exists($CONFIG['LOGERRORFILE']) && !touch($CONFIG['LOGERRORFILE']))){
				throw new FatalMisconfigurationException('The configured LOGERRORFILE can not be modified.');
			}

			// check ownership on the (eventually) just created files
			Utils::FixFileOwner($CONFIG['LOGFILE']);
			Utils::FixFileOwner($CONFIG['LOGERRORFILE']);
		}else{
			$CONFIG['LOGBACKEND_CLASS'] = $CONFIG['LOGBACKEND'];
		}
	}

}