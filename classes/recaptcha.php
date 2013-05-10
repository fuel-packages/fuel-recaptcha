<?php
/*
 * This is a PHP library that handles calling reCAPTCHA.
 *    - Documentation and latest version
 *          http://recaptcha.net/plugins/php/
 *    - Get a reCAPTCHA API Key
 *          http://recaptcha.net/api/getkey
 *    - Discussion group
 *          http://groups.google.com/group/recaptcha
 *
 * Copyright (c) 2007 reCAPTCHA -- http://recaptcha.net
 * AUTHORS:
 *   Mike Crawford
 *   Ben Maurer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
* ReCaptcha modified to integrate with Fuel
*
* @package     Fuel
* @subpackage  Packages
* @category    Captcha
* @author      Power Head <p0w3rhead@gmail.com>
*/

namespace ReCaptcha;

class ReCaptcha
{
	public static function instance()
	{
		static $instance = null;

		if ($instance === null)
		{
			$instance = new static;
		}

		return $instance;
	}

	public static function _init()
	{
		\Config::load('recaptcha', true);
	}

	/**
	 * @var	contains error string
	 */
	protected $_error;

	/**
    * Calls an HTTP POST function to verify if the user's guess was correct
    * @param string $privkey
    * @param string $remoteip
    * @param string $challenge
    * @param string $response
    * @param array $extra_params an array of extra variables to post to the server
    * @return bool
    */
	function check_answer ($remoteip, $challenge, $response, $extra_params = array())
	{

		if (\Config::get('recaptcha.private_key') == '')
		{
			throw new \Exception('You did not supply an API key for Recaptcha');
			return false;
		}

		if ($remoteip == null || $remoteip == '')
		{
			throw new \Exception('For security reasons, you must pass the remote ip to reCAPTCHA');
			return false;
		}

		if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0)
		{
			$this->_error = 'Incorrect captcha';
			return false;
		}

		$response = $this->_http_post(
			\Config::get('recaptcha.verify_server'),
			"/recaptcha/api/verify",
			array (
				'privatekey' => \Config::get('recaptcha.private_key'),
				'remoteip' => $remoteip,
				'challenge' => $challenge,
				'response' => $response
			) + $extra_params
		);

		$answers = explode ("\n", $response[1]);

		if (trim($answers[0]) == 'true')
		{
			return true;
		}
		else
		{
			$this->_error = $answers[1];
			return false;
		}
	}

	/**
	 * Gets the challenge HTML (javascript and non-javascript version).
	 * @param string $pubkey A public key for reCAPTCHA
	 * @param string $error The error given by reCAPTCHA (optional, default is null)
	 * @param boolean $use_ssl Should the request be made over ssl? (optional, default is false)
	 * @return string - The HTML to be embedded in the user's form.
   */

	static function get_html ($use_ssl = false)
	{

		if (\Config::get('recaptcha.public_key') == '')
		{
			throw new \Exception('You did not supply an API key for Recaptcha');
		}

		if ($use_ssl)
		{
			$server = \Config::get('recaptcha.secure_server');
		}
		else
		{
			$server = \Config::get('recaptcha.server');
		}

		$html = \View::forge('form')
			->set('server', $server)
			->set('public_key', \Config::get('recaptcha.public_key'));

		return $html;
	}

	/**
	 * Encodes the given data into a query string format
	 * @param $data - array of string elements to be encoded
	 * @return string - encoded request
	 */
	function _qsencode($data)
	{
		return http_build_query($data);
	}

	/**
	 * Submits an HTTP POST to a reCAPTCHA server
	 * @param string $host
	 * @param string $path
	 * @param array $data
	 * @param int port
	 * @return array response
	 */
	function _http_post($host, $path, $data, $port = 80)
	{
		$req = $this->_qsencode($data);

		$http_request = implode('',array(
			"POST $path HTTP/1.0\r\n",
			"Host: $host\r\n",
			"Content-Type: application/x-www-form-urlencoded;\r\n",
			"Content-Length:".strlen($req)."\r\n",
			"User-Agent: reCAPTCHA/PHP\r\n",
			"\r\n",
		$req));

		$response = '';
		if( false == ( $fs = @fsockopen($host, $port, $errno, $errstr, 10) ) )
		{
			throw new \Exception('Could not open socket');
			return false;
		}

		fwrite($fs, $http_request);
		while (!feof($fs))
		{
			$response .= fgets($fs, 1160); // One TCP-IP packet
		}
		fclose($fs);
		$response = explode("\r\n\r\n", $response, 2);
		return $response;
	}

	/**
	 * Returns error
	 * @return string
	 */
	public function get_error()
	{
		if ($this->_error) return $this->_error;
	}
}
