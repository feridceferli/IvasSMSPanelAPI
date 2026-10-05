#Copyright @ISmartCoder
#Updates Channel t.me/TheSmartDev
from flask import Flask, request, jsonify
from datetime import datetime
import cloudscraper
import json
from bs4 import BeautifulSoup
import logging
import os
import gzip
from io import BytesIO
import brotli
import time
from urllib.parse import urlparse, urljoin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IVASSMSClient:
    def __init__(self):
        self.scraper = cloudscraper.create_scraper()
        self.base_url = "https://www.ivasms.com"
        self.logged_in = False
        self.csrf_token = None
        self.auth_error = None
        self.last_login_attempt = 0
        
        self.scraper.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        })

    def decompress_response(self, response):
        """Decompress response content if encoded with gzip or brotli."""
        # requests/cloudscraper already decode HTTP Content-Encoding.
        return response.text

    def load_cookies(self, file_path="cookies.json"):
        try:
            if os.getenv("COOKIES_JSON"):
                cookies_raw = json.loads(os.getenv("COOKIES_JSON"))
                logger.debug("Loaded cookies from environment variable")
            else:
                with open(file_path, 'r') as file:
                    cookies_raw = json.load(file)
                    logger.debug("Loaded cookies from file")
            
            if isinstance(cookies_raw, dict):
                logger.debug("Cookies loaded as dictionary")
                return cookies_raw
            elif isinstance(cookies_raw, list):
                cookies = {}
                for cookie in cookies_raw:
                    if 'name' in cookie and 'value' in cookie:
                        cookies[cookie['name']] = cookie['value']
                logger.debug("Cookies loaded as list")
                return cookies
            else:
                logger.error("Cookies are in an unsupported format")
                raise ValueError("Cookies are in an unsupported format.")
        except FileNotFoundError:
            logger.error("cookies.json file not found")
            return None
        except json.JSONDecodeError:
            logger.error("Invalid JSON format in cookies.json")
            return None
        except Exception as e:
            logger.error("IVAS operation failed")
            return None

    def login_with_cookies(self, cookies_file="cookies.json"):
        self.logged_in = False
        self.csrf_token = None
        self.last_login_attempt = time.monotonic()
        cookies = self.load_cookies(cookies_file)
        if not cookies or not all(isinstance(k, str) and isinstance(v, str)
                                  for k, v in cookies.items()):
            self.auth_error = "invalid_cookie_configuration"
            logger.error("IVAS authentication: invalid_cookie_configuration")
            return False

        self.scraper.cookies.clear()
        for name, value in cookies.items():
            self.scraper.cookies.set(name, value, domain="www.ivasms.com")

        try:
            response = self.scraper.get(
                f"{self.base_url}/portal/sms/received", timeout=10)
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            path = urlparse(response.url).path
            if response.status_code == 403:
                challenge = (response.headers.get("cf-mitigated", "").lower() == "challenge"
                             or "/cdn-cgi/challenge-platform/" in html)
                self.auth_error = ("upstream_challenge" if challenge
                                   else "upstream_forbidden")
            elif response.status_code != 200:
                self.auth_error = "upstream_http_error"
            elif "login" in path.lower() or soup.select_one('input[type="password"]'):
                self.auth_error = "session_expired_or_invalid"
            else:
                token = soup.find("input", {"name": "_token"})
                if token and token.get("value"):
                    self.csrf_token = token["value"]
                    self.logged_in = True
                    self.auth_error = None
                    logger.info("IVAS authentication successful")
                    return True
                self.auth_error = "csrf_token_missing"
            # Never log response bodies, cookies, tokens, or response headers.
            logger.error("IVAS authentication: %s; http_status=%s",
                         self.auth_error, response.status_code)
        except Exception:
            self.auth_error = "upstream_connection_error"
            logger.error("IVAS authentication: upstream_connection_error")
        return False

    def authenticate(self):
        """Prefer configured credentials; otherwise retain cookie authentication."""
        email = os.getenv("IVAS_EMAIL", "")
        password = os.getenv("IVAS_PASSWORD", "")
        if not email and not password:
            return self.login_with_cookies()
        self.logged_in = False
        self.csrf_token = None
        self.last_login_attempt = time.monotonic()
        if not email or not password:
            self.auth_error = "missing_login_credentials"
            return False
        try:
            response = self.scraper.get(f"{self.base_url}/login", timeout=10)
            if response.status_code != 200:
                self.auth_error = ("upstream_challenge" if
                    response.headers.get("cf-mitigated", "").lower() == "challenge"
                    or "/cdn-cgi/challenge-platform/" in response.text
                    else "upstream_forbidden" if response.status_code == 403
                    else "upstream_http_error")
                logger.error("IVAS credential login: %s; http_status=%s",
                             self.auth_error, response.status_code)
                return False
            soup = BeautifulSoup(response.text, "html.parser")
            password_input = soup.select_one('input[type="password"][name]')
            form = password_input.find_parent("form") if password_input else None
            if form is None:
                self.auth_error = "login_form_missing"
                return False
            if form.select_one('.g-recaptcha, .cf-turnstile, [name="g-recaptcha-response"]'):
                self.auth_error = "interactive_verification_required"
                return False
            email_input = form.select_one('input[type="email"][name], input[name="email"]')
            if email_input is None or form.get("method", "get").lower() != "post":
                self.auth_error = "unsupported_login_form"
                return False
            action = urljoin(response.url, form.get("action") or response.url)
            target = urlparse(action)
            if target.scheme != "https" or target.hostname not in ("www.ivasms.com", "ivasms.com"):
                self.auth_error = "unsafe_login_action"
                return False
            payload = {item["name"]: item.get("value", "")
                       for item in form.select('input[type="hidden"][name]')}
            payload[email_input["name"]] = email
            payload[password_input["name"]] = password
            result = self.scraper.post(action, data=payload, timeout=10)
            if result.status_code != 200:
                self.auth_error = "credential_login_rejected"
                logger.error("IVAS credential login rejected; http_status=%s", result.status_code)
                return False
            # Validate the protected page instead of treating a login-page token as success.
            protected = self.scraper.get(f"{self.base_url}/portal/sms/received", timeout=10)
            page = BeautifulSoup(protected.text, "html.parser")
            token = page.find("input", {"name": "_token"})
            if protected.status_code != 200 or "login" in urlparse(protected.url).path.lower() or page.select_one('input[type="password"]'):
                self.auth_error = "credential_login_not_authenticated"
                return False
            if not token or not token.get("value"):
                self.auth_error = "csrf_token_missing"
                return False
            self.csrf_token = token["value"]
            self.logged_in = True
            self.auth_error = None
            logger.info("IVAS credential authentication successful")
            return True
        except Exception:
            self.auth_error = "upstream_connection_error"
            logger.error("IVAS credential login connection failed")
            return False

    def check_otps(self, from_date="", to_date=""):
        if not self.logged_in:
            logger.error("Not logged in")
            return None
        
        if not self.csrf_token:
            logger.error("No CSRF token available")
            return None
        
        logger.debug("IVAS operation completed")
        try:
            payload = {
                'from': from_date,
                'to': to_date,
                '_token': self.csrf_token
            }
            
            headers = {
                'Accept': 'text/html, */*; q=0.01',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': self.base_url,
                'Referer': f"{self.base_url}/portal/sms/received"
            }
            
            response = self.scraper.post(
                f"{self.base_url}/portal/sms/received/getsms",
                data=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.debug("Successfully retrieved SMS data")
                html_content = self.decompress_response(response)
                soup = BeautifulSoup(html_content, 'html.parser')
                
                count_sms = soup.select_one("#CountSMS").text if soup.select_one("#CountSMS") else '0'
                paid_sms = soup.select_one("#PaidSMS").text if soup.select_one("#PaidSMS") else '0'
                unpaid_sms = soup.select_one("#UnpaidSMS").text if soup.select_one("#UnpaidSMS") else '0'
                revenue_sms = soup.select_one("#RevenueSMS").text.replace(' USD', '') if soup.select_one("#RevenueSMS") else '0'
                
                sms_details = []
                items = soup.select("div.item")
                for item in items:
                    country_number = item.select_one(".col-sm-4").text.strip()
                    count = item.select_one(".col-3:nth-child(2) p").text.strip()
                    paid = item.select_one(".col-3:nth-child(3) p").text.strip()
                    unpaid = item.select_one(".col-3:nth-child(4) p").text.strip()
                    revenue = item.select_one(".col-3:nth-child(5) p span.currency_cdr").text.strip()
                    
                    sms_details.append({
                        'country_number': country_number,
                        'count': count,
                        'paid': paid,
                        'unpaid': unpaid,
                        'revenue': revenue
                    })
                
                result = {
                    'count_sms': count_sms,
                    'paid_sms': paid_sms,
                    'unpaid_sms': unpaid_sms,
                    'revenue': revenue_sms,
                    'sms_details': sms_details
                }
                result['raw_response'] = html_content
                logger.debug("IVAS operation completed")
                return result
            logger.error("IVAS operation failed")
            return None
        except Exception as e:
            logger.error("IVAS operation failed")
            return None

    def get_sms_details(self, phone_range, from_date="", to_date=""):
        if not self.logged_in:
            logger.error("Not logged in")
            return None
        
        logger.debug("IVAS operation completed")
        try:
            payload = {
                '_token': self.csrf_token,
                'start': from_date,
                'end': to_date,
                'range': phone_range
            }
            
            headers = {
                'Accept': 'text/html, */*; q=0.01',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': self.base_url,
                'Referer': f"{self.base_url}/portal/sms/received"
            }
            
            response = self.scraper.post(
                f"{self.base_url}/portal/sms/received/getsms/number",
                data=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                html_content = self.decompress_response(response)
                soup = BeautifulSoup(html_content, 'html.parser')
                number_details = []
                items = soup.select("div.card.card-body")
                for item in items:
                    phone_number = item.select_one(".col-sm-4").text.strip()
                    count = item.select_one(".col-3:nth-child(2) p").text.strip()
                    paid = item.select_one(".col-3:nth-child(3) p").text.strip()
                    unpaid = item.select_one(".col-3:nth-child(4) p").text.strip()
                    revenue = item.select_one(".col-3:nth-child(5) p span.currency_cdr").text.strip()
                    onclick = item.select_one(".col-sm-4").get('onclick', '')
                    id_number = onclick.split("'")[3] if onclick else ''
                    
                    number_details.append({
                        'phone_number': phone_number,
                        'count': count,
                        'paid': paid,
                        'unpaid': unpaid,
                        'revenue': revenue,
                        'id_number': id_number
                    })
                logger.debug("IVAS operation completed")
                return number_details
            logger.error("IVAS operation failed")
            return None
        except Exception as e:
            logger.error("IVAS operation failed")
            return None

    def get_otp_message(self, phone_number, phone_range, from_date="", to_date=""):
        if not self.logged_in:
            logger.error("Not logged in")
            return None
        
        logger.debug("IVAS operation completed")
        try:
            payload = {
                '_token': self.csrf_token,
                'start': from_date,
                'end': to_date,
                'Number': phone_number,
                'Range': phone_range
            }
            
            headers = {
                'Accept': 'text/html, */*; q=0.01',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': self.base_url,
                'Referer': f"{self.base_url}/portal/sms/received"
            }
            
            response = self.scraper.post(
                f"{self.base_url}/portal/sms/received/getsms/number/sms",
                data=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                html_content = self.decompress_response(response)
                soup = BeautifulSoup(html_content, 'html.parser')
                message = soup.select_one(".col-9.col-sm-6 p").text.strip() if soup.select_one(".col-9.col-sm-6 p") else None
                logger.debug("IVAS operation completed")
                return message
            logger.error("IVAS operation failed")
            return None
        except Exception as e:
            logger.error("IVAS operation failed")
            return None

    def get_all_otp_messages(self, sms_details, from_date="", to_date="", limit=None):
        all_otp_messages = []
        
        logger.debug("IVAS operation completed")
        for detail in sms_details:
            phone_range = detail['country_number']
            number_details = self.get_sms_details(phone_range, from_date, to_date)
            
            if number_details:
                for number_detail in number_details:
                    if limit is not None and len(all_otp_messages) >= limit:
                        logger.debug("IVAS operation completed")
                        return all_otp_messages
                    phone_number = number_detail['phone_number']
                    otp_message = self.get_otp_message(phone_number, phone_range, from_date, to_date)
                    if otp_message:
                        all_otp_messages.append({
                            'range': phone_range,
                            'phone_number': phone_number,
                            'otp_message': otp_message
                        })
                        logger.debug("IVAS operation completed")
            else:
                logger.warning("No SMS number details returned")
        
        logger.debug("IVAS operation completed")
        return all_otp_messages

app = Flask(__name__)
client = IVASSMSClient()

with app.app_context():
    if not client.authenticate():
        logger.error("Failed to initialize client with cookies")

@app.route('/')
def welcome():
    return jsonify({
        'message': 'Welcome to the IVAS SMS API',
        'status': 'API is alive',
        'endpoints': {
            '/sms': 'Get OTP messages for a specific date (format: DD/MM/YYYY) with optional limit. Example: /sms?date=01/05/2025&limit=10'
        }
    })

@app.route('/sms')
def get_sms():
    date_str = request.args.get('date')
    limit = request.args.get('limit')
    
    if not date_str:
        return jsonify({
            'error': 'Date parameter is required in DD/MM/YYYY format'
        }), 400
    
    try:
        parsed_date = datetime.strptime(date_str, '%d/%m/%Y') 
        from_date = date_str
        to_date = request.args.get('to_date', '')
        if to_date:
            datetime.strptime(to_date, '%d/%m/%Y')  
    except ValueError:
        return jsonify({
            'error': 'Invalid date format. Use DD/MM/YYYY'
        }), 400

    if limit:
        try:
            limit = int(limit)
            if limit <= 0:
                return jsonify({
                    'error': 'Limit must be a positive integer'
                }), 400
        except ValueError:
            return jsonify({
                'error': 'Limit must be a valid integer'
            }), 400
    else:
        limit = None

    if not client.logged_in:
        if time.monotonic() - client.last_login_attempt >= 60:
            client.authenticate()
        if not client.logged_in:
            return jsonify({
                'error': 'Client not authenticated',
                'reason': client.auth_error,
                'retry_after_seconds': 60
            }), 503
    
    logger.debug("IVAS operation completed")
    result = client.check_otps(from_date=from_date, to_date=to_date)
    
    if not result:
        return jsonify({
            'error': 'Failed to fetch OTP data'
        }), 500

    otp_messages = client.get_all_otp_messages(result.get('sms_details', []), from_date=from_date, to_date=to_date, limit=limit)
    
    return jsonify({
        'status': 'success',
        'from_date': from_date,
        'to_date': to_date or 'Not specified',
        'limit': limit if limit is not None else 'Not specified',
        'sms_stats': {
            'count_sms': result['count_sms'],
            'paid_sms': result['paid_sms'],
            'unpaid_sms': result['unpaid_sms'],
            'revenue': result['revenue']
        },
        'otp_messages': otp_messages
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
