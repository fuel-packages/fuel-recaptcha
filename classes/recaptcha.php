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
* @author      Indzign
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
	function check_answer ($remoteip, $challenge)
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

		if ($challenge == null || strlen($challenge) == 0)
		{
			$this->_error = 'Incorrect captcha';
			return false;
		}

		$response = $this->send(
			array (
				'secret' => \Config::get('recaptcha.private_key'),
				'response' => $challenge,
				'remoteip' => $remoteip,
			) 
		);
		
		return $response->success;
	}
	

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
	 * Submits an HTTP POST to a reCAPTCHA server
	 * @param string $host
	 * @param string $path
	 * @param array $data
	 * @param int port
	 * @return array response
	 */
	
    function send($data)
    {
    # Create a connection
    $ch = curl_init("https://www.google.com/recaptcha/api/siteverify"); 
    # Form data string
    $postString = http_build_query($data, '', '&');
    # Setting our options
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postString);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    # Get the response and decode as json object
    $response = json_decode(curl_exec($ch));
    curl_close($ch);
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
