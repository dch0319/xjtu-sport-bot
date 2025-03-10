import random
import ssl
from email.mime.multipart import MIMEMultipart

import requests
import logging
import time
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import json
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os


# 配置信息
class Config:
    # 用户信息
    USER = os.environ.get('USER')  # 学号
    PASSWORD = os.environ.get('PASSWORD')  # 密码

    # 涵英楼北草坪固定坐标
    # LONGITUDE = 108.654387  # 经度
    # LATITUDE = 34.257229  # 纬度

    # 邮件配置
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
    SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
    RECEIVER_EMAIL = os.environ.get('RECEIVER_EMAIL')
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    SMTP_PORT = int(os.environ.get('SMTP_PORT'))

    # 加密公钥，无需修改
    AES_PUBLIC_KEY = "0725@pwdorgopenp"

    # 日志配置
    LOG_FILE = os.path.join(os.path.dirname(__file__), "sport_bot.log")
    LOG_LEVEL = logging.INFO

    @staticmethod
    def get_random_longitude():
        """生成随机经度"""
        return round(random.uniform(108.654367, 108.654407), 6)

    @staticmethod
    def get_random_latitude():
        """生成随机纬度"""
        return round(random.uniform(34.257209, 34.257249), 6)


# 初始化日志
logging.basicConfig(
    filename=Config.LOG_FILE,
    level=Config.LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8",
)


# 前端界面的加密函数
def aes_ecb_encrypt(pwd_val: str, public_key=Config.AES_PUBLIC_KEY) -> str:
    key = public_key.encode("utf-8")
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(pwd_val.encode("utf-8"), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode("utf-8")


def get_token(user, password):
    try:
        # Step 1: 获取初始Cookie
        response = requests.get(
            "https://org.xjtu.edu.cn/openplatform/oauth/authorize",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            },
            params={
                "appId": "1740",
                "redirectUri": "https://ipahw.xjtu.edu.cn/sso/callback",
                "responseType": "code",
                "scope": "user_info",
                "state": "1234",
            },
            allow_redirects=False,
        )
        cookies = response.cookies.get_dict()

        # Step 2: 获取验证码Cookie
        response = requests.post(
            "https://org.xjtu.edu.cn/openplatform/g/admin/getJcaptchaCode",
            headers={
                "Cookie": f"route={cookies['route']}; rdstate={cookies['rdstate']}; cur_appId_={cookies['cur_appId_']}; state={cookies['state']}",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            },
        )
        cookies.update(response.cookies.get_dict())

        # Step 3: 执行登录
        response = requests.post(
            "https://org.xjtu.edu.cn/openplatform/g/admin/login",
            headers={
                "Cookie": f"route={cookies['route']}; rdstate={cookies['rdstate']}; cur_appId_={cookies['cur_appId_']}; state={cookies['state']}; JSESSIONID={cookies['JSESSIONID']}; sid_code={cookies['sid_code']}",
                "Content-Type": "application/json;charset=UTF-8",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            },
            data=json.dumps(
                {
                    "loginType": 1,
                    "username": user,
                    "pwd": password,
                    "jcaptchaCode": "",
                }
            ),
        )
        response_json = response.json()
        if not response_json["message"] == "成功":
            raise Exception("统一身份认证登录失败")

        # Step 4-5: 获取最终token
        cookies["open_Platform_User"] = response_json["data"]["tokenKey"]
        response = requests.get(
            "https://org.xjtu.edu.cn/openplatform/oauth/auth/getRedirectUrl",
            params={
                "userType": "1",
                "personNo": user,
                "_": str(int(time.time() * 1000)),
            },
            headers={"Cookie": "; ".join([f"{k}={v}" for k, v in cookies.items()])},
        )
        oauth_code = parse_qs(urlparse(response.json()["data"]).query)["code"][0]

        response = requests.get(
            "https://ipahw.xjtu.edu.cn/szjy-boot/sso/codeLogin",
            params={"userType": "1", "code": oauth_code, "employeeNo": user},
            headers={"Referer": response.json()["data"]},
        )
        return response.json()["data"]["token"]

    except Exception as e:
        logging.error(f"Token获取失败: {str(e)}")
        return None


def sign_operation(url, payload, token, operation_name):
    try:
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/537.36",
                "token": token,
            },
            data=json.dumps(payload),
        )
        logging.info(f"{operation_name}请求: {response.status_code}")

        if response.status_code == 200:
            response_data = response.json()
            if response_data.get("success"):
                logging.info(f"{operation_name}成功")
                return True
            logging.warning(f"{operation_name}失败: {response_data.get('msg')}")
        return False
    except Exception as e:
        logging.error(f"{operation_name}异常: {str(e)}")
        return False


class Email_message:
    def __init__(self, sender_email: str, sender_password: str, receiver_email: str, smtp_server: str,
                 smtp_port: int) -> None:
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.receiver_email = receiver_email
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def send_email(self, header: str, content: str) -> bool:
        try:
            message = MIMEMultipart()
            message['Subject'] = Header(f"体美劳运动打卡{header}", "utf-8")
            message['From'] = self.sender_email
            message['To'] = self.receiver_email
            msg_content = MIMEText(content, 'plain', 'utf-8')
            message.attach(msg_content)

            # Create secure connection with server and send email
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context) as server:
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, self.receiver_email, message.as_string())
            return True
        except smtplib.SMTPException as e:
            print('send email error', e)
            return False


def main():
    smtp = Email_message(Config.SENDER_EMAIL, Config.SENDER_PASSWORD, Config.RECEIVER_EMAIL,
                         Config.SMTP_SERVER, Config.SMTP_PORT)
    # 获取加密后的密码
    crypto_pwd = aes_ecb_encrypt(Config.PASSWORD)

    # 获取访问令牌
    token = get_token(Config.USER, crypto_pwd)
    if not token:
        logging.error("获取token失败，终止流程")
        smtp.send_email("失败", "获取token失败，请检查账号密码")
        return

    # 执行签到
    sign_in_success = sign_operation(
        "https://ipahw.xjtu.edu.cn/szjy-boot/api/v1/sportActa/signRun",
        {
            "sportType": 2,
            "longitude": Config.get_random_longitude(),
            "latitude": Config.get_random_latitude(),
            "courseInfoId": "null",
        },
        token,
        "签到",
    )

    if sign_in_success:
        random_minutes = random.randint(31, 45)
        random_seconds = random.randint(0, 59)
        total_wait_time = random_minutes * 60 + random_seconds
        logging.info(f"等待{random_minutes}分钟{random_seconds}秒后签退...")
        time.sleep(total_wait_time)

        sign_out_success = sign_operation(
            "https://ipahw.xjtu.edu.cn/szjy-boot/api/v1/sportActa/signOutTrain",
            {"longitude": Config.get_random_longitude(), "latitude": Config.get_random_latitude()},
            token,
            "签退",
        )
        header = "成功" if sign_out_success else "失败"
        notice_msg = "打卡成功" if sign_out_success else "签到成功但签退失败"
    else:
        header = "失败"
        notice_msg = "签到失败"

    smtp.send_email(header, notice_msg)


if __name__ == "__main__":
    main()
