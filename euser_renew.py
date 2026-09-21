#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EUserv 自动续期脚本 - 多账号多线程版本
支持多账号配置、多线程并发处理、自动登录、验证码识别、检查到期状态、自动续期并发送 Telegram 通知
"""

import os
import hashlib
import hmac
import base64
import struct

import sys
import io
import re
import json
import time
import threading
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from html import escape
from concurrent.futures import ThreadPoolExecutor, as_completed

from PIL import Image
import ddddocr
import requests
from bs4 import BeautifulSoup
from imap_tools import MailBox, AND

from dotenv import load_dotenv
if os.path.exists('dev.env'):
    load_dotenv('dev.env')

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 兼容新版 Pillow
if not hasattr(Image, 'ANTIALIAS'):
    Image.ANTIALIAS = Image.Resampling.LANCZOS

# 全局 OCR 实例（线程安全）
ocr = ddddocr.DdddOcr(beta=True, show_ad=False)
ocr_lock = threading.Lock()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"


# ============== 工具函数 ==============
def resolve_imap_server(email: str) -> str:
    """
    根据邮箱域名自动推断 IMAP 服务器。
    未知自定义域名时通过 DNS-over-HTTPS 查询 MX，并识别常见邮箱服务商。
    """
    IMAP_MAP = {
        'gmail.com':       'imap.gmail.com',
        'googlemail.com':  'imap.gmail.com',
        'outlook.com':     'outlook.office365.com',
        'hotmail.com':     'outlook.office365.com',
        'live.com':        'outlook.office365.com',
        'msn.com':         'outlook.office365.com',
        'yahoo.com':       'imap.mail.yahoo.com',
        'yahoo.co.uk':     'imap.mail.yahoo.co.uk',
        'yahoo.co.jp':     'imap.mail.yahoo.co.jp',
        'icloud.com':      'imap.mail.me.com',
        'me.com':          'imap.mail.me.com',
        'mac.com':         'imap.mail.me.com',
        'qq.com':          'imap.qq.com',
        '163.com':         'imap.163.com',
        '126.com':         'imap.126.com',
        'sina.com':        'imap.sina.com',
        'foxmail.com':     'imap.qq.com',
        'protonmail.com':  'imap.protonmail.com',
        'proton.me':       'imap.protonmail.com',
        'zoho.com':        'imap.zoho.com',
        'aol.com':         'imap.aol.com',
        'gmx.com':         'imap.gmx.com',
        'gmx.de':          'imap.gmx.net',
        'web.de':          'imap.web.de',
        't-online.de':     'secureimap.t-online.de',
    }
    if not email or '@' not in email:
        return 'imap.gmail.com'

    domain = email.strip().lower().split('@')[-1]
    direct = IMAP_MAP.get(domain)
    if direct:
        return direct

    # 自定义域名：查询 MX，避免错误地假设 imap.<domain> 一定存在。
    mx_hosts = []
    try:
        doh = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            headers={"accept": "application/dns-json"},
            timeout=10,
        )
        doh.raise_for_status()
        payload = doh.json()
        for answer in payload.get("Answer", []) or []:
            data = str(answer.get("data", "")).strip()
            # MX data: "10 mail.example.com."
            match = re.match(r'\s*\d+\s+([^\s]+)', data)
            if match:
                mx_hosts.append(match.group(1).rstrip('.').lower())
        if mx_hosts:
            logger.info(f"📮 {domain} MX: {', '.join(mx_hosts[:5])}")
    except Exception as exc:
        logger.warning(f"⚠️ 查询 {domain} MX 失败: {exc}")

    mx_blob = " ".join(mx_hosts)
    if any(x in mx_blob for x in ('google.com', 'googlemail.com')):
        logger.info("📮 检测到 Google Workspace，使用 imap.gmail.com")
        return 'imap.gmail.com'
    if any(x in mx_blob for x in ('protection.outlook.com', 'outlook.com', 'microsoft.com')):
        logger.info("📮 检测到 Microsoft 365，使用 outlook.office365.com")
        return 'outlook.office365.com'
    if 'zoho.eu' in mx_blob:
        logger.info("📮 检测到 Zoho Mail EU，使用 imap.zoho.eu")
        return 'imap.zoho.eu'
    if 'zoho' in mx_blob:
        logger.info("📮 检测到 Zoho Mail，使用 imap.zoho.com")
        return 'imap.zoho.com'
    if any(x in mx_blob for x in ('icloud.com', 'me.com')):
        logger.info("📮 检测到 iCloud Mail，使用 imap.mail.me.com")
        return 'imap.mail.me.com'
    if 'fastmail' in mx_blob or 'messagingengine.com' in mx_blob:
        logger.info("📮 检测到 Fastmail，使用 imap.fastmail.com")
        return 'imap.fastmail.com'
    if 'protonmail' in mx_blob:
        logger.warning("⚠️ 检测到 Proton Mail；云端 GitHub Actions 无法直接连接 Proton Bridge")
        return 'imap.protonmail.com'
    if 'mx.cloudflare.net' in mx_blob:
        # Cloudflare Email Routing 只有转发功能，没有该域名自己的 IMAP 邮箱。
        logger.error(
            "❌ 检测到 Cloudflare Email Routing：该自定义域名没有可登录的 IMAP。"
            "请配置 EMAIL_PIN 为实际收件邮箱地址，并将 EMAIL_PASS 设置为该邮箱的应用密码。"
        )
        return 'imap.cloudflare-routing.invalid'

    fallback = f'imap.{domain}'
    logger.warning(
        f"⚠️ 未识别邮箱服务商，暂用 {fallback}。"
        "如该域名只是邮件转发，请设置 EMAIL_PIN 为实际收件邮箱。"
    )
    return fallback



def load_notification_state() -> Dict:
    """读取通知去重状态；不存在或损坏时回退为空状态。"""
    if not os.path.exists(NOTIFICATION_STATE_FILE):
        return {}
    try:
        with open(NOTIFICATION_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning(f"⚠️ 通知状态文件读取失败，将重新建立: {exc}")
        return {}


def save_notification_state(state: Dict):
    """原子写入通知状态。"""
    temp_path = NOTIFICATION_STATE_FILE + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(temp_path, NOTIFICATION_STATE_FILE)
    except Exception as exc:
        logger.warning(f"⚠️ 通知状态文件保存失败: {exc}")
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


def should_send_manual_reminder(
    state: Dict,
    account_email: str,
    order_id: str,
    interval_days: int = PAID_REMINDER_INTERVAL_DAYS,
) -> bool:
    """同一账号/合同的人工处理提醒按间隔去重。"""
    key = f"{account_email}:{order_id}"
    last_value = state.get("manual_reminders", {}).get(key)
    if not last_value:
        return True
    try:
        last_date = datetime.strptime(last_value, "%Y-%m-%d").date()
        return (datetime.utcnow().date() - last_date).days >= interval_days
    except Exception:
        return True


def mark_manual_reminder_sent(state: Dict, account_email: str, order_id: str):
    key = f"{account_email}:{order_id}"
    state.setdefault("manual_reminders", {})[key] = datetime.utcnow().strftime("%Y-%m-%d")


# ============== 配置数据类 ==============
class AccountConfig:
    """
    单个账号配置。
    email_pin: 用于接收 PIN 码的邮箱（可选）。
               未配置时自动使用 email 字段。
    imap_server: IMAP 服务器地址（可选）。
                 未配置时根据 email_pin（或 email）的域名自动推断。
    email_password: email_pin 邮箱的密码 / Gmail 应用专用密码。
    """
    def __init__(self, email, password, email_pin='', email_password='', imap_server=''):
        self.email = email
        self.password = password
        # email_pin 未配置则回退到 email
        self.email_pin = email_pin if email_pin else email
        self.email_password = email_password if email_password else password
        # imap_server 未配置则自动推断
        if imap_server:
            self.imap_server = imap_server
        else:
            self.imap_server = resolve_imap_server(self.email_pin)


class GlobalConfig:
    """全局配置"""
    def __init__(self, telegram_bot_token="", telegram_chat_id="", bark_url="", max_workers=3, max_login_retries=3):
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.bark_url = bark_url  # 新增：Bark 推送 URL
        self.max_workers = max_workers
        self.max_login_retries = max_login_retries


# ============== 配置区 ==============
# 全局配置
GLOBAL_CONFIG = GlobalConfig(
    telegram_bot_token=os.getenv("TG_BOT_TOKEN"),   # TG 的 API Token
    telegram_chat_id=os.getenv("TG_CHAT_ID"),        # TG 的 User ID
    bark_url=os.getenv("BARK_URL"),                  # iOS Bark 推送，格式：https://api.day.app/your_key/
    max_workers=int(os.getenv("MAX_WORKERS", 3)),
    max_login_retries=int(os.getenv("MAX_LOGIN_RETRIES", 5)),
)

# 自动续期安全策略：
# - 永远只允许明确识别为 FREE 的产品自动续期；
# - 如果配置 AUTO_RENEW_CONTRACTS，则还必须命中合同号白名单。
AUTO_RENEW_CONTRACTS = {
    item.strip()
    for item in os.getenv("AUTO_RENEW_CONTRACTS", "").split(",")
    if item.strip()
}
PAID_REMINDER_INTERVAL_DAYS = max(
    1, int(os.getenv("PAID_REMINDER_INTERVAL_DAYS", "7"))
)
NOTIFICATION_STATE_FILE = os.getenv(
    "NOTIFICATION_STATE_FILE", "notification_state.json"
)


def load_accounts_from_env() -> List[AccountConfig]:
    """
    动态从环境变量加载账号，支持任意数量。
    第 1 个账号：EUSERV_EMAIL / EUSERV_PASSWORD / EMAIL_PIN / EMAIL_PASS
    第 N 个账号：EUSERV_EMAILN / EUSERV_PASSWORDN / EMAIL_PINN / EMAIL_PASSN（N >= 2）
    只要 EUSERV_EMAIL 存在即继续读取，遇到第一个空缺则停止。
    """
    accounts = []
    i = 1
    while True:
        suffix = "" if i == 1 else str(i)
        email = os.getenv(f"EUSERV_EMAIL{suffix}")
        if not email or not email.strip():
            break
        password = os.getenv(f"EUSERV_PASSWORD{suffix}")
        accounts.append(AccountConfig(
            email=email,
            password=password,
            email_pin=os.getenv(f"EMAIL_PIN{suffix}"),       # 可选，未配置则使用 EUSERV_EMAIL
            email_password=os.getenv(f"EMAIL_PASS{suffix}"),  # PIN 邮箱的密码（Gmail 应用专用密码等）
        ))
        i += 1
    return accounts


# 账号列表 - 动态从环境变量加载
# EMAIL_PIN：可选，用于接收登录/续期 PIN 码的邮箱，未配置则使用 EUSERV_EMAIL
# IMAP 服务器根据 EMAIL_PIN（或 EUSERV_EMAIL）域名自动推断，如需覆盖可在 AccountConfig 中手动指定
ACCOUNTS = load_accounts_from_env()

# ====================================


# 数字字符纠正映射表（用于操作数）—— 模块级常量，避免每次调用重建
_DIGIT_CORRECTIONS: Dict[str, str] = {
    'O': '0', 'o': '0',  # 字母O → 数字0
    'D': '0', 'Q': '0',  # D/Q可能是0
    'I': '1', 'i': '1', 'l': '1', '|': '1',  # I/l/竖线 → 数字1
    'Z': '2', 'z': '2',  # 字母Z → 数字2
    'S': '5', 's': '5',  # 字母S → 数字5
    'G': '6', 'b': '6',  # 字母G → 数字6
    'B': '8', 'g': '8',  # 字母B → 数字8
}

# 运算符映射表（用于中间位置）—— 模块级常量
_OPERATOR_CORRECTIONS: Dict[str, str] = {
    'T': '+', 't': '+', 'F': '+', 'f': '+', 'r': '+',  # T → 加号
    'I': '-', 'i': '-', '|': '-', '1': '-', 'l': '-',  # 竖线类 → 减号
    'x': '×', 'X': '×',  # x/X → 乘号
    '*': '×', '×': '×',  # 统一乘号
    '÷': '/', ':': '/',  # 统一除号
    '+': '+', '-': '-', '/': '/',  # 保留原有运算符
}


def recognize_and_calculate(captcha_image_url: str, session: requests.Session) -> Optional[str]:
    """识别并计算验证码（线程安全）"""
    
    def aggressive_digit_convert(text: str) -> str:
        """激进的数字转换：尽可能把所有字符转为数字"""
        result = []
        for char in text:
            if char.isdigit():
                result.append(char)
            elif char in _DIGIT_CORRECTIONS:
                result.append(_DIGIT_CORRECTIONS[char])
            elif char.upper() in _DIGIT_CORRECTIONS:
                result.append(_DIGIT_CORRECTIONS[char.upper()])
            else:
                result.append(char)
        return ''.join(result)
    
    logger.info("正在处理验证码...")
    try:
        logger.debug("尝试自动识别验证码...")
        response = session.get(captcha_image_url)
        img = Image.open(io.BytesIO(response.content)).convert('RGB')

        # 颜色过滤（numpy 向量化：保留橙色文字，噪点变白）
        try:
            import numpy as np
            arr = np.array(img, dtype=np.uint8)
            mask = ~((arr[:, :, 0] > 200) & (arr[:, :, 1] > 100) & (arr[:, :, 1] < 220) & (arr[:, :, 2] < 80))
            arr[mask] = [255, 255, 255]
            img = Image.fromarray(arr)
            width, height = img.size
        except ImportError:
            # numpy 不可用时回退到逐像素处理
            pixels = img.load()
            width, height = img.size
            for x in range(width):
                for y in range(height):
                    r, g, b = pixels[x, y]
                    if not (r > 200 and 100 < g < 220 and b < 80):
                        pixels[x, y] = (255, 255, 255)
        
        # 转灰度 + 二值化
        img = img.convert('L')
        threshold = 200
        img = img.point(lambda x: 0 if x < threshold else 255, '1')
        
        # 去边框（numpy 向量化直接切片置白）
        try:
            import numpy as np
            border = 10
            arr2 = np.array(img.convert('L'), dtype=np.uint8)
            arr2[:border, :] = 255
            arr2[-border:, :] = 255
            arr2[:, :border] = 255
            arr2[:, -border:] = 255
            img = Image.fromarray(arr2).point(lambda x: 0 if x < 128 else 255, '1')
        except ImportError:
            border = 10
            pixels = img.load()
            for x in range(width):
                for y in range(height):
                    if x < border or x >= width - border or y < border or y >= height - border:
                        pixels[x, y] = 255
        
        output = io.BytesIO()
        img.save(output, format='PNG')
        processed_bytes = output.getvalue()
        
        # OCR 识别（加锁保证线程安全）
        with ocr_lock:
            text = ocr.classification(processed_bytes, png_fix=True).strip()
        
        logger.debug(f"OCR 原始识别: {text}")

        # 预处理：去除空格
        raw_text = text.strip().replace(' ', '')
        text_len = len(raw_text)
        
        logger.info(f"验证码长度: {text_len}, 内容: {raw_text}")
        
        # ===== 情况1：长度 >= 6，按纯字母数字验证码处理 =====
        if text_len >= 6:
            logger.info(f"检测到 >= 6 位验证码，按纯字母数字处理: {raw_text}")
            return raw_text.upper()  # 统一大写返回
        
        # ===== 情况2：长度 < 6，按运算验证码处理 =====
        logger.info(f"检测到 < 6 位验证码，按运算验证码处理: {raw_text}")
        
        # 尝试多种解析策略
        # 策略1：标准3位格式 (数字 运算符 数字)
        if text_len == 3:
            left_char, mid_char, right_char = raw_text[0], raw_text[1], raw_text[2]
            
            # 左右转数字，中间转运算符
            left_corrected = _DIGIT_CORRECTIONS.get(left_char, left_char)
            right_corrected = _DIGIT_CORRECTIONS.get(right_char, right_char)
            op_char = _OPERATOR_CORRECTIONS.get(mid_char, mid_char)
            
            logger.debug(f"3位纠正: '{left_char}'→'{left_corrected}' '{mid_char}'→'{op_char}' '{right_char}'→'{right_corrected}'")
            
            if left_corrected.isdigit() and right_corrected.isdigit():
                result = calculate_operation(int(left_corrected), op_char, int(right_corrected), raw_text)
                if result is not None:
                    return result
        
        # 策略2：正则匹配运算表达式（支持多位数）
        # 先进行字符纠正
        corrected_text = raw_text
        for old, new in _DIGIT_CORRECTIONS.items():
            corrected_text = corrected_text.replace(old, new)
        
        # 匹配模式：数字 + 运算符 + 数字
        pattern = r'^(\d+)([+\-×*/÷:xX])(\d+)$'
        match = re.match(pattern, corrected_text)
        
        if match:
            left_str, op, right_str = match.groups()
            op = _OPERATOR_CORRECTIONS.get(op, op)  # 运算符纠正
            
            left = int(left_str)
            right = int(right_str)
            
            logger.debug(f"正则匹配成功: {left} {op} {right}")
            result = calculate_operation(left, op, right, raw_text)
            if result is not None:
                return result
        
        # 策略3：激进纠正 - 强制把所有非数字转为数字，再尝试解析
        logger.warning("常规解析失败，尝试激进纠正...")
        aggressive_text = aggressive_digit_convert(raw_text)
        logger.debug(f"激进纠正结果: {raw_text} → {aggressive_text}")
        
        # 如果纠正后全是数字，尝试按位置推断运算符
        if aggressive_text.isdigit() and len(aggressive_text) >= 3:
            # 假设：倒数第二位可能是被误识别的运算符
            # 例如："253" 可能是 "2+3"（中间的5被误识别）
            if len(aggressive_text) == 3:
                left = int(aggressive_text[0])
                right = int(aggressive_text[2])
                # 尝试常见运算符
                for op in ['+', '-', '×', '/']:
                    result = calculate_operation(left, op, right, raw_text, silent=True)
                    if result is not None and 0 <= int(result) <= 20:  # 结果在合理范围
                        logger.info(f"激进推断成功: {left} {op} {right} = {result}")
                        return result
        
        # 策略4：如果还有字母，再次尝试强制转换
        if not aggressive_text.isdigit():
            logger.warning(f"包含无法转换的字符: {aggressive_text}")
            # 最后尝试：移除所有非数字非运算符字符
            cleaned = re.sub(r'[^0-9+\-×*/÷]', '', corrected_text)
            match = re.match(r'^(\d+)([+\-×*/÷])(\d+)$', cleaned)
            if match:
                left_str, op, right_str = match.groups()
                result = calculate_operation(int(left_str), op, int(right_str), raw_text)
                if result is not None:
                    logger.info(f"清理后解析成功: {cleaned}")
                    return result
        
        # 所有策略都失败，返回原始文本
        logger.warning(f"所有解析策略均失败，返回原始文本: {raw_text}")
        return raw_text
        
    except Exception as e:
        logger.error(f"验证码识别发生错误: {e}", exc_info=True)
        return None


def calculate_operation(left: int, op: str, right: int, raw_text: str, silent: bool = False) -> Optional[str]:
    """
    执行运算并返回结果
    silent: 是否静默模式（不输出日志，用于批量尝试）
    """
    try:
        if op == '+':
            result = left + right
            op_name = '加'
        elif op == '-':
            result = left - right
            op_name = '减'
        elif op in {'×', '*', 'x', 'X'}:
            result = left * right
            op_name = '乘'
        elif op in {'/', '÷', ':'}:
            if right == 0:
                if not silent:
                    logger.warning("除数为0，无法计算")
                return None
            if left % right != 0:
                if not silent:
                    logger.warning(f"除法非整除: {left} ÷ {right} = {left / right}")
                return None
            result = left // right
            op_name = '除'
        else:
            if not silent:
                logger.warning(f"未知运算符: {op}")
            return None
        
        if not silent:
            logger.info(f"验证码计算: {left} {op_name} {right} = {result}")
        return str(result)
    except Exception as e:
        if not silent:
            logger.error(f"计算错误: {e}")
        return None








def generate_totp(secret: str, digits: int = 6, period: int = 30) -> Optional[str]:
    """生成标准 RFC 6238 TOTP（SHA1/6位/30秒），用于 EUserv Authenticator PIN。"""
    if not secret:
        return None
    try:
        normalized = re.sub(r'[^A-Z2-7=]', '', secret.upper())
        normalized = normalized.rstrip('=')
        normalized += '=' * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized, casefold=True)
        counter = int(time.time() // period)
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(binary % (10 ** digits)).zfill(digits)
    except Exception as exc:
        logger.error(f"❌ TOTP 密钥解析失败: {exc}")
        return None

def get_euserv_pin(email: str, email_password: str, imap_server: str,
                   max_retries: int = 6, retry_interval: int = 5,
                   max_age_seconds: int = 90) -> Optional[str]:
    """从邮箱获取 EUserv PIN 码（带轮询重试 + 时效性校验）

    因 PIN 邮件可能有延迟，会按 retry_interval 秒间隔最多重试 max_retries 次。
    只接受 max_age_seconds 秒内发送的 PIN，避免拿到旧 PIN 导致续期失败。

    Args:
        email: 邮箱地址
        email_password: 邮箱密码
        imap_server: IMAP 服务器地址
        max_retries: 最大重试次数（默认 6 次）
        retry_interval: 每轮间隔秒数（默认 5 秒）
        max_age_seconds: 最大 PIN 邮件时效（默认 90 秒，超过则跳过等待新邮件）
    """
    cutoff = datetime.now() - timedelta(seconds=max_age_seconds)
    for attempt in range(1, max_retries + 1):
        try:
            if attempt > 1:
                logger.info(f"PIN 邮件尚未到达，{retry_interval} 秒后第 {attempt}/{max_retries} 次重试...")
                time.sleep(retry_interval)

            logger.info(f"正在从邮箱 {email} 获取 PIN 码（第 {attempt}/{max_retries} 次）...")
            with MailBox(imap_server, timeout=15).login(email, email_password) as mailbox:
                for msg in mailbox.fetch(AND(from_='no-reply@euserv.com', body='PIN'), limit=1, reverse=True):
                    logger.debug(f"找到邮件: {msg.subject}, 收件时间: {msg.date_str}")

                    # ★ 时效性校验：跳过旧邮件，等新的 PIN 邮件
                    msg_date = msg.date
                    if msg_date and msg_date.replace(tzinfo=None) < cutoff:
                        logger.info(f"PIN 邮件时间 {msg_date} 超过 {max_age_seconds}s，可能为旧 PIN，等待新邮件...")
                        continue

                    match = re.search(r'PIN:\s*\n?(\d{6})', msg.text)
                    if match:
                        pin = match.group(1)
                        logger.info("✅ 已成功提取 PIN（内容已隐藏）")
                        return pin
                    else:
                        match_fallback = re.search(r'(\d{6})', msg.text)
                        if match_fallback:
                            pin = match_fallback.group(1)
                            logger.warning("⚠️ 已通过备选规则提取 PIN（内容已隐藏）")
                            return pin

        except Exception as e:
            logger.warning(f"第 {attempt} 次获取 PIN 时出错: {e}")
            if attempt < max_retries:
                time.sleep(retry_interval)
                continue
            logger.error(f"获取 PIN 码失败（已重试 {max_retries} 次）")
            return None

    logger.warning("❌ 未找到符合条件的 EUserv 邮件")
    return None


class EUserv:
    """EUserv 操作类"""

    # Cookie 文件保存目录
    COOKIE_DIR = "cookies"

    def __init__(self, config: AccountConfig):
        self.config = config
        self.session = requests.Session()
        self.sess_id = None
        self.c_id = None
        # 合同元数据：产品名称、是否免费。只有明确识别为 free 的合同才允许自动续期。
        self.server_meta = {}
        # 每个账号对应一个独立的 cookie 文件
        os.makedirs(self.COOKIE_DIR, exist_ok=True)
        safe_name = hashlib.md5(config.email.encode()).hexdigest()
        self.cookie_file = os.path.join(self.COOKIE_DIR, f"{safe_name}.json")
        # 初始化时尝试加载已保存的 Cookie（让服务器识别为受信任设备，跳过 PIN）
        self._load_cookies()

    def _save_cookies(self):
        """将当前 session 的 Cookie 持久化到文件（保留完整属性）"""
        try:
            cookies = [
                {
                    'name':    c.name,
                    'value':   c.value,
                    'domain':  c.domain or 'support.euserv.com',
                    'path':    c.path or '/',
                    'expires': c.expires,
                    'secure':  c.secure,
                }
                for c in self.session.cookies
            ]
            with open(self.cookie_file, 'w', encoding='utf-8') as f:
                json.dump(cookies, f)
            logger.info(f"✅ 信任设备 Cookie 已保存: {self.cookie_file}")
        except Exception as e:
            logger.warning(f"⚠️ 保存 Cookie 失败: {e}")

    def _load_cookies(self):
        """从文件加载 Cookie 到 session，兼容旧版 name→value 格式"""
        if not os.path.exists(self.cookie_file):
            return
        try:
            with open(self.cookie_file, 'r', encoding='utf-8') as f:
                cookies = json.load(f)
            # 兼容旧格式 {"name": "value", ...}
            if isinstance(cookies, dict):
                for name, value in cookies.items():
                    self.session.cookies.set(name, value, domain='support.euserv.com')
            else:
                # 新格式：完整属性列表
                for c in cookies:
                    self.session.cookies.set(
                        c['name'], c['value'],
                        domain=c.get('domain', 'support.euserv.com'),
                        path=c.get('path', '/'),
                    )
            logger.info("🍪 已加载信任设备 Cookie，登录时将跳过 PIN 验证")
        except Exception as e:
            logger.warning(f"⚠️ 加载 Cookie 失败: {e}")

    def login(self) -> bool:
        """登录 EUserv（支持验证码和 PIN，Cookie 持久化跳过 PIN）"""
        logger.info(f"正在登录账号: {self.config.email}")

        headers = {
            'user-agent': USER_AGENT,
            'origin': 'https://www.euserv.com'
        }
        url = "https://support.euserv.com/index.iphp"
        captcha_url = "https://support.euserv.com/securimage_show.php"

        def _auth_page_diag(resp, stage: str):
            try:
                dsoup = BeautifulSoup(resp.text, "html.parser")
                plain = dsoup.get_text(" ", strip=True)
                low = plain.lower()
                input_names = sorted({
                    tag.get('name') for tag in dsoup.find_all('input')
                    if tag.get('name')
                })
                flags = {
                    'password_form': bool(dsoup.find('input', {'name': 'password'})),
                    'captcha': 'captcha' in low or 'securimage' in resp.text.lower(),
                    'pin': 'pin' in low,
                    '2fa': any(x in low for x in ('authenticator', 'two-factor', '2fa', 'verification code')),
                    'logout': 'logout' in low,
                    'customer_id': 'customer id:' in low,
                }
                title = dsoup.title.get_text(" ", strip=True) if dsoup.title else ''
                logger.info(
                    f"认证页面诊断[{stage}]: title='{title[:80]}', "
                    f"flags={flags}, inputs={input_names[:20]}"
                )
                # 只输出验证相关句子，避免泄露邮箱/客户资料
                sentences = re.split(r'(?<=[.!?])\s+|\n+', plain)
                hints = []
                for sentence in sentences:
                    sl = sentence.lower()
                    if any(k in sl for k in (
                        'captcha', 'pin', 'authenticator', 'two-factor',
                        'verification', 'login process', 'security check'
                    )):
                        clean = re.sub(r'[\w.+-]+@[\w.-]+', '***@***', sentence)
                        clean = re.sub(r'\b\d{5,}\b', '***', clean)
                        hints.append(clean[:240])
                if hints:
                    logger.info(f"认证提示[{stage}]: {hints[:6]}")
            except Exception as exc:
                logger.debug(f"认证页面诊断失败: {exc}")

        def _is_authenticated(resp) -> bool:
            soup_check = BeautifulSoup(resp.text, "html.parser")
            plain_check = soup_check.get_text(" ", strip=True).lower()
            has_password_form = bool(soup_check.find('input', {'name': 'password'}))
            has_logout = 'logout' in plain_check
            has_customer_panel = (
                'customer id:' in plain_check
                or 'contracts/ orders' in plain_check
                or 'please choose a contract to manage' in plain_check
            )
            return (not has_password_form) and has_logout and has_customer_panel

        try:
            # 获取 sess_id（session 里已携带 Cookie，服务器可识别为受信任设备）
            sess = self.session.get(url, headers=headers, timeout=30)

            def _current_php_session():
                values = [c.value for c in self.session.cookies if c.name == 'PHPSESSID' and c.value]
                return values[-1] if values else None

            cookie_sess_id = _current_php_session()
            sess_id_match = re.search(r'sess_id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,100})["\']?', sess.text)
            if not sess_id_match:
                sess_id_match = re.search(r'sess_id=([a-zA-Z0-9]{20,100})', sess.text)

            html_sess_id = sess_id_match.group(1) if sess_id_match else None
            sess_id = cookie_sess_id or html_sess_id
            if not sess_id:
                logger.error("❌ 无法获取 EUserv 会话 ID（PHPSESSID/sess_id 均缺失）")
                return False

            if cookie_sess_id and html_sess_id and cookie_sess_id != html_sess_id:
                logger.info("检测到 Cookie PHPSESSID 与页面 sess_id 不同，优先使用 Cookie 会话")
            logger.debug("已获取有效 EUserv 会话 ID（内容已隐藏）")

            # 访问 logo
            logo_png_url = "https://support.euserv.com/pic/logo_small.png"
            self.session.get(logo_png_url, headers=headers, timeout=30)

            # 提交登录表单
            login_data = {
                'email': self.config.email,
                'password': self.config.password,
                'form_selected_language': 'en',
                'Submit': 'Login',
                'subaction': 'login',
                'sess_id': sess_id
            }

            logger.debug("提交登录表单...")
            response = self.session.post(url, headers=headers, data=login_data, timeout=30)
            response.raise_for_status()
            _auth_page_diag(response, "password-submit")

            # 解析返回页面
            soup = BeautifulSoup(response.text, "html.parser")

            # 检查登录错误
            if 'Please check email address/customer ID and password' in response.text:
                logger.error("❌ 用户名或密码错误")
                return False
            if 'kc2_login_iplock_cdown' in response.text:
                logger.error("❌ 密码错误次数过多，账号被锁定，请5分钟后重试")
                return False

            # 处理验证码
            if 'captcha' in response.text.lower():
                logger.info("⚠️ 需要验证码，正在识别...")

                max_captcha_retries = 10
                for captcha_attempt in range(max_captcha_retries):
                    if captcha_attempt > 0:
                        logger.warning(f"验证码识别失败，第 {captcha_attempt + 1}/{max_captcha_retries} 次重试...")
                        time.sleep(3)

                    captcha_code = recognize_and_calculate(captcha_url, self.session)

                    if not captcha_code:
                        logger.error("❌ 验证码识别失败")
                        return False

                    captcha_data = {
                        'subaction': 'login',
                        'sess_id': sess_id,
                        'captcha_code': captcha_code
                    }

                    response = self.session.post(url, headers=headers, data=captcha_data, timeout=30)
                    response.raise_for_status()

                    if 'captcha' in response.text.lower():
                        logger.warning(f"❌ 验证码错误（第 {captcha_attempt + 1} 次）")
                        if captcha_attempt < max_captcha_retries - 1:
                            continue
                        else:
                            logger.error("❌ 验证码错误次数过多，重新进入登录流程")
                            return False
                    else:
                        soup = BeautifulSoup(response.text, "html.parser")
                        logger.info("✅ 验证码验证成功")
                        break

            # 处理 PIN 验证
            # 若之前 Cookie 有效，服务器不会返回 PIN 页面，直接跳过这段
            pin_soup = BeautifulSoup(response.text, "html.parser")
            has_pin_input = bool(
                pin_soup.find('input', {'name': 'pin'})
                or pin_soup.find('input', {'name': 'auth'})
            )
            pin_text = pin_soup.get_text(" ", strip=True).lower()
            authenticator_prompt = any(marker in pin_text for marker in (
                'authenticator app',
                'shown in your authenticator',
                'shown in yout authenticator',
                'two-factor authentication',
                '2fa'
            ))
            email_pin_prompt = any(marker in pin_text for marker in (
                'pin that you receive via email',
                'pin sent to',
                'pin for the confirmation',
                'confirmation of a security check'
            ))

            if has_pin_input or authenticator_prompt or email_pin_prompt:
                c_id_tag = pin_soup.find("input", {"name": "c_id"})
                if c_id_tag:
                    self.c_id = c_id_tag.get("value")

                sess_tag = pin_soup.find("input", {"name": "sess_id"})
                if sess_tag and sess_tag.get("value"):
                    sess_id = sess_tag.get("value")

                if authenticator_prompt:
                    logger.info("🔐 EUserv 要求 Authenticator 动态 PIN")
                    totp_secret = os.getenv("EUSERV_TOTP_SECRET", "").strip()
                    if not totp_secret:
                        logger.error(
                            "❌ 未配置 EUSERV_TOTP_SECRET，无法通过 EUserv Authenticator 两步验证"
                        )
                        return False
                    pin = generate_totp(totp_secret)
                    if not pin:
                        logger.error("❌ 无法生成 Authenticator TOTP")
                        return False
                    logger.info("✅ 已生成当前 Authenticator 动态 PIN")
                else:
                    logger.info("📧 EUserv 要求邮箱 PIN")
                    time.sleep(8)
                    pin = get_euserv_pin(
                        self.config.email_pin,
                        self.config.email_password,
                        self.config.imap_server,
                        max_retries=2,
                        retry_interval=5,
                        max_age_seconds=90
                    )
                    if not pin:
                        logger.error("❌ 获取邮箱 PIN 码失败")
                        return False

                login_confirm_data = {
                    'pin': pin,
                    'auth': pin,
                    'save_for_auto_login': 'on',
                    'sess_id': sess_id,
                    'Submit': 'Confirm',
                    'subaction': 'login',
                }
                if self.c_id:
                    login_confirm_data['c_id'] = self.c_id

                response = self.session.post(
                    url, headers=headers, data=login_confirm_data, timeout=30
                )
                response.raise_for_status()
                _auth_page_diag(response, "second-factor-submit")

                if _is_authenticated(response):
                    self._save_cookies()
                    logger.info("✅ EUserv 两步验证成功")
                else:
                    logger.error("❌ EUserv 两步验证提交后仍未进入控制面板")
                    return False

            # 严格检查登录成功：必须没有密码表单，同时存在 Logout + 客户控制面板特征。
            if _is_authenticated(response):
                current_cookie_session = _current_php_session()
                if current_cookie_session:
                    if current_cookie_session != sess_id:
                        logger.info("登录后 PHPSESSID 已更新，切换到最新会话")
                    sess_id = current_cookie_session
                logger.info(f"✅ 账号 {self.config.email} 登录成功（已验证控制面板会话）")
                self.sess_id = sess_id
                return True
            else:
                _auth_page_diag(response, "final-not-authenticated")
                logger.error(f"❌ 账号 {self.config.email} 登录失败：未建立有效控制面板会话")
                return False

        except Exception as e:
            logger.error(f"❌ 登录过程出现异常: {e}", exc_info=True)
            return False
    


    def update_info(self):
            # 支持通过环境变量 UPDATE_INFO_DAYS 自定义触发日（逗号分隔），默认 2,22
            _days_str = os.getenv("UPDATE_INFO_DAYS", "2,22")
            try:
                _update_days = {int(d.strip()) for d in _days_str.split(',') if d.strip().isdigit()}
            except Exception:
                _update_days = {2, 22}
            if not _update_days:
                _update_days = {2, 22}

            current_day = datetime.now().day
            if current_day not in _update_days:
                return True  # 非更新日不是失败

            logger.info("更新用户信息...")
            try:
                # 1. 进入用户信息界面
                url = f"https://support.euserv.com/index.iphp?sess_id={self.sess_id}&action=show_customerdata"
                headers = {
                    'user-agent': USER_AGENT,
                    'host': 'support.euserv.com',
                    'referer': f'https://support.euserv.com/index.iphp?sess_id={self.sess_id}&subaction=show_kwk_main'
                }

                logger.info("进入用户界面...")
                response = self.session.get(url=url, headers=headers)
                response.raise_for_status()

                soup = BeautifulSoup(response.text, 'html.parser')

                # ── 工具函数 ────────────────────────────────────────────────
                def _val(name):
                    """读取 text/hidden input 的 value，找不到返回空串。"""
                    tag = soup.find('input', {'name': name})
                    return tag.get('value', '').strip() if tag else ''

                def _sel(selector):
                    """读取 select 中选中 option 的 value，找不到返回空串。"""
                    opt = soup.select_one(f'{selector} option[selected]')
                    return opt.get('value', '') if opt else ''

                def _checkbox(name):
                    """
                    checkbox：已勾选返回 value（通常为 '1'），未勾选返回 None。
                    None 表示该字段不应出现在 POST body 里（与浏览器行为一致）。
                    """
                    tag = soup.find('input', {'name': name, 'type': 'checkbox'})
                    if tag and tag.get('checked') is not None:
                        return tag.get('value', '1')
                    return None

                def _vals(name):
                    """读取同名 input 列表（c_birthday[]、c_phone[]、c_fax[]）。"""
                    return [t.get('value', '').strip() for t in soup.find_all('input', {'name': name})]

                # ── 提取 c_id ────────────────────────────────────────────────
                if not self.c_id:
                    self.c_id = _val('c_id')

                # ── 修复🔴：新增 c_fname / c_lname ────────────────────────────
                c_fname = _val('c_fname')
                c_lname = _val('c_lname')

                # ── 修复🟡：动态读取 c_ustid[]（text + select 各一个）─────────
                c_ustid_text = [t.get('value', '') for t in soup.find_all('input', {'name': 'c_ustid[]'})]
                c_ustid_sel  = [
                    (s.find('option', selected=True) or {}).get('value', '')
                    for s in soup.find_all('select', {'name': 'c_ustid[]'})
                ]
                c_ustid_value = c_ustid_text + c_ustid_sel  # 保持与表单顺序一致

                # ── 修复🟢：c_org 动态读取，不再硬编码为空 ────────────────────
                c_org = _val('c_org')

                # ── 普通字段 ─────────────────────────────────────────────────
                c_att                  = _sel('#c_att')
                c_street               = _val('c_street')
                c_streetno             = _val('c_streetno')
                c_postal               = _val('c_postal')
                c_city                 = _val('c_city')
                c_country              = _sel('#c_country')
                c_phone_country_prefix = _val('c_phone_country_prefix')
                c_phone_password       = _val('c_phone_password')
                c_fax_country_prefix   = _val('c_fax_country_prefix')
                c_website              = _val('c_website')
                c_firstcontact         = _sel('#c_firstcontact')
                c_forumnick            = _val('c_forumnick')
                c_hrno                 = _val('c_hrno')
                c_hrcourt              = _val('c_hrcourt')
                c_taxid                = _val('c_taxid')
                c_identifier           = _val('c_identifier')
                c_birthplace           = _val('c_birthplace')
                c_country_of_birth     = _sel('#c_country_of_birth')

                # ── 修复🟢：列表字段用列表推导，避免无效的 Tag truthy 判断 ────
                c_birthday_value = _vals('c_birthday[]')
                c_phone_value    = _vals('c_phone[]')
                c_fax_value      = _vals('c_fax[]')

                # ── 修复🔴：checkbox 按浏览器语义处理 ────────────────────────
                c_tac_date          = _checkbox('c_tac_date')
                c_emailabo_contract = _checkbox('c_emailabo_contract')
                c_emailabo_products = _checkbox('c_emailabo_products')

                # ── 构造 POST body ────────────────────────────────────────────
                upInfo_data = {
                    'sess_id':               self.sess_id,
                    'subaction':             'kc2_customer_data_update',
                    'c_id':                  self.c_id,
                    'c_fname':               c_fname,           # 🔴 新增
                    'c_lname':               c_lname,           # 🔴 新增
                    'c_org':                 c_org,             # 🟢 动态
                    'c_ustid[]':             c_ustid_value,     # 🟡 动态
                    'c_att':                 c_att,
                    'c_street':              c_street,
                    'c_streetno':            c_streetno,
                    'c_postal':              c_postal,
                    'c_city':                c_city,
                    'c_country':             c_country,
                    'c_birthday[]':          c_birthday_value,
                    'c_phone_country_prefix': c_phone_country_prefix,
                    'c_phone[]':             c_phone_value,
                    'c_phone_password':      c_phone_password,
                    'c_fax_country_prefix':  c_fax_country_prefix,
                    'c_fax[]':               c_fax_value,
                    'c_website':             c_website,
                    'c_firstcontact':        c_firstcontact,
                    'c_forumnick':           c_forumnick,
                    'c_hrno':                c_hrno,
                    'c_hrcourt':             c_hrcourt,
                    'c_taxid':               c_taxid,
                    'c_identifier':          c_identifier,
                    'c_birthplace':          c_birthplace,
                    'c_country_of_birth':    c_country_of_birth,
                }

                # 🔴 checkbox 未勾选时不传（与浏览器行为一致）
                if c_tac_date is not None:
                    upInfo_data['c_tac_date'] = c_tac_date
                if c_emailabo_contract is not None:
                    upInfo_data['c_emailabo_contract'] = c_emailabo_contract
                if c_emailabo_products is not None:
                    upInfo_data['c_emailabo_products'] = c_emailabo_products

                # ── 提交 ─────────────────────────────────────────────────────
                logger.info("提交保存用户信息...")
                response = self.session.post(
                    url='https://support.euserv.com/index.iphp',
                    headers=headers,
                    data=upInfo_data
                )
                response.raise_for_status()

                if 'customer data has been changed' in response.text:
                    logger.info("✅ 保存用户信息成功")
                else:
                    logger.warning(f"⚠️ 保存用户信息失败，response={response.text[:500]}")
                return True

            except Exception as e:
                logger.error(f"❌ 更新用户信息异常: {e}", exc_info=True)
                return False


    def _classify_contract(self, product_name: str, context_text: str = '') -> Dict:
        """
        合同安全分类：
        - 只有产品名/上下文明确定义为 free 才允许自动续期；
        - 其他一律视为 paid_or_unknown，只提醒、不执行续期。
        """
        product = (product_name or '').strip()
        # 产品名只保留套餐名称，去掉 Servername / IP 等运行信息，Telegram 更简洁。
        product = re.split(
            r'\s+(?:Servername:|IPv4:|IPv6:|Hostname:|IP:)',
            product,
            maxsplit=1,
            flags=re.I
        )[0].strip()
        context = (context_text or '').strip()
        combined = f"{product} {context}".lower()

        is_free = bool(re.search(r'(?<![a-z0-9])free(?![a-z0-9])', combined))
        return {
            'product_name': product or '未知产品',
            'is_free': is_free,
            'billing_type': 'free' if is_free else 'paid_or_unknown',
        }

    def _remember_contract_meta(self, order_id: str, product_name: str, context_text: str = ''):
        meta = self._classify_contract(product_name, context_text)
        existing = self.server_meta.get(str(order_id))
        # 优先保留更具体的产品名；free 识别一旦成立则保留。
        if existing:
            if existing.get('product_name') not in ('', '未知产品') and meta.get('product_name') == '未知产品':
                meta['product_name'] = existing.get('product_name')
            if existing.get('is_free'):
                meta['is_free'] = True
                meta['billing_type'] = 'free'
        self.server_meta[str(order_id)] = meta
        logger.info(
            f"合同 {order_id} 分类: "
            f"{meta['product_name']} / "
            f"{'FREE 自动续期' if meta['is_free'] else '付费或未知，仅提醒'}"
        )

    def _extract_order_id_from_container(self, container, fallback_ids=None) -> Optional[str]:
        """从订单/通知容器中提取合同号，兼容新版 EUserv Notifications 页面。"""
        if container is None:
            return None

        blobs = []
        try:
            for tag in container.find_all(True):
                for attr in (
                    'href', 'onclick', 'value', 'id', 'name',
                    'data-ord-no', 'data-order-id', 'data-ord-id'
                ):
                    value = tag.get(attr)
                    if value:
                        blobs.append(str(value))
        except Exception:
            pass

        patterns = (
            r'(?:ord_no|ord_id|order_id)[^0-9]{0,12}(\d{4,10})',
            r'(?:contract|order)[^0-9]{0,12}(\d{4,10})',
        )
        for blob in blobs:
            for pattern in patterns:
                match = re.search(pattern, blob, re.I)
                if match:
                    return match.group(1)

        text = " ".join(container.stripped_strings)
        # 新版通知行通常形如：442244 vServer ... automatically deactivated ... extend contract
        candidates = re.findall(r'\b(\d{5,10})\b', text)
        for candidate in candidates:
            try:
                number = int(candidate)
            except ValueError:
                continue
            if 2000 <= number <= 2099:  # 排除日期中的年份
                continue
            return candidate

        if fallback_ids and len(fallback_ids) == 1:
            return next(iter(fallback_ids))
        return None

    def _load_contract_pages(self):
        """读取控制面板并自动跟随 Contracts 导航。优先依赖登录 Cookie，不强制 sess_id。"""
        if not self.sess_id:
            return []

        headers = {'user-agent': USER_AGENT, 'origin': 'https://www.euserv.com'}
        pages = []
        seen_urls = set()

        def _fetch(url):
            if not url or url in seen_urls:
                return None
            seen_urls.add(url)
            response = self.session.get(url=url, headers=headers, timeout=30)
            response.raise_for_status()
            pages.append(response)
            return response

        try:
            # EUserv 主要依赖 PHPSESSID Cookie。先访问无参数入口，避免错误/过期 sess_id 覆盖有效 Cookie。
            entry_urls = [
                "https://support.euserv.com/index.iphp",
                f"https://support.euserv.com/index.iphp?sess_id={self.sess_id}",
            ]
            initial_pages = []
            for entry in entry_urls:
                try:
                    response = _fetch(entry)
                    if response is not None:
                        initial_pages.append(response)
                except Exception as exc:
                    logger.warning(f"控制面板入口读取失败: {exc}")

            for first in initial_pages:
                soup = BeautifulSoup(first.text, 'html.parser')
                contract_links = []
                for link in soup.find_all('a', href=True):
                    label = link.get_text(" ", strip=True).lower()
                    if (
                        label == 'contracts'
                        or label.startswith('contracts ')
                        or 'contracts/ orders' in label
                    ):
                        contract_links.append(link.get('href'))

                if contract_links:
                    logger.info(f"检测到 Contracts 导航链接: {len(contract_links)} 个")

                for href in contract_links[:5]:
                    full_url = requests.compat.urljoin("https://support.euserv.com/", href)
                    safe_href = re.sub(r'(sess_id=)[^&]+', r'\1***', href)
                    logger.info(f"正在进入 Contracts 页面: {safe_href}")
                    try:
                        contract_page = _fetch(full_url)
                    except Exception as exc:
                        logger.warning(f"进入 Contracts 页面失败: {exc}")
                        continue

                    if contract_page is None:
                        continue

                    # 跟随合同页中可能存在的第二层 Contracts/Orders 导航。
                    csoup = BeautifulSoup(contract_page.text, 'html.parser')
                    for link2 in csoup.find_all('a', href=True):
                        label2 = link2.get_text(" ", strip=True).lower()
                        if label2 == 'contracts' or 'contracts/ orders' in label2:
                            full2 = requests.compat.urljoin(
                                "https://support.euserv.com/", link2.get('href')
                            )
                            try:
                                _fetch(full2)
                            except Exception:
                                pass

            # 无敏感诊断：判断到底拿到了哪一类页面
            if pages:
                last = pages[-1]
                lsoup = BeautifulSoup(last.text, 'html.parser')
                title = lsoup.title.get_text(" ", strip=True) if lsoup.title else ''
                plain = lsoup.get_text(" ", strip=True).lower()
                logger.info(
                    "控制面板诊断: "
                    f"pages={len(pages)}, len={len(last.text)}, title='{title[:80]}', "
                    f"logout={'logout' in plain}, login_form={bool(lsoup.find('input', {'name': 'password'}))}, "
                    f"customer={'customer' in plain}, contract={'contract' in plain}"
                )

            return pages

        except Exception as exc:
            logger.warning(f"读取合同页面失败: {exc}")
            return pages

    def _get_manual_extension_state(self, order_id: str) -> Tuple[str, str]:
        """
        返回新版 Notifications 中指定合同的手动续期状态：
        ('required', 'YYYY-MM-DD') = 仍显示停用警告，需要续期
        ('clear', '')              = 合同页已正常读取且该合同警告消失
        ('error', '')              = 页面读取/解析失败，不能据此判成功
        """
        if not self.sess_id:
            return ('error', '')

        pages = self._load_contract_pages()
        if not pages:
            return ('error', '')

        saw_contract_panel = False
        warning_re = re.compile(
            r'automatically deactivated on\s+(20\d{2}-\d{2}-\d{2})',
            re.I
        )

        for response in pages:
            soup = BeautifulSoup(response.text, 'html.parser')
            plain = soup.get_text(" ", strip=True)
            plain_low = plain.lower()

            logged_in_markers = (
                'contracts/ orders', 'customer id:', 'customer-/contractdata',
                'please choose a contract to manage', 'contract extension'
            )
            if any(marker in plain_low for marker in logged_in_markers):
                saw_contract_panel = True

            fallback_ids = set(re.findall(r'\bContract:\s*(\d{4,10})\b', plain, re.I))

            for row in soup.find_all('tr'):
                row_text = " ".join(row.stripped_strings)
                m = warning_re.search(row_text)
                if not m:
                    continue
                row_id = self._extract_order_id_from_container(row, fallback_ids)
                if row_id == str(order_id):
                    return ('required', m.group(1))

            for link in soup.find_all('a'):
                if 'extend contract' not in link.get_text(" ", strip=True).lower():
                    continue
                container = link.find_parent(['tr', 'div', 'section', 'li']) or link.parent
                if container is None:
                    continue
                container_text = " ".join(container.stripped_strings)
                m = warning_re.search(container_text)
                if not m:
                    continue
                row_id = self._extract_order_id_from_container(container, fallback_ids)
                if row_id == str(order_id):
                    return ('required', m.group(1))

        if saw_contract_panel:
            return ('clear', '')
        logger.warning("续期状态复核：未能进入可识别的合同管理页面")
        return ('error', '')

    def get_servers(self) -> Dict[str, Tuple[bool, str]]:
        """获取合同列表，同时兼容旧订单表和新版 Notifications/Contract extension。"""
        logger.info(f"正在获取账号 {self.config.email} 的服务器列表...")
        self.server_meta = {}

        if not self.sess_id:
            logger.error("❌ 未登录")
            return {}

        try:
            pages = self._load_contract_pages()
            servers = {}

            if not pages:
                logger.error("❌ 无法读取 EUserv 合同页面")
                return {}

            warning_re = re.compile(
                r'automatically deactivated on\s+(20\d{2}-\d{2}-\d{2})',
                re.I
            )

            for page_index, response in enumerate(pages, 1):
                soup = BeautifulSoup(response.text, 'html.parser')
                plain = soup.get_text(" ", strip=True)

                # 1) 旧版/传统合同表：全页面扫描
                for tr in soup.select('.kc2_order_table.kc2_content_table tr'):
                    server_id_cells = tr.select('.td-z1-sp1-kc')
                    if len(server_id_cells) != 1:
                        continue

                    server_id_text = server_id_cells[0].get_text(strip=True)
                    if not re.fullmatch(r'\d{4,10}', server_id_text or ''):
                        continue

                    row_text = " ".join(tr.stripped_strings)
                    # 尽量从合同表中提取产品名；无法精确时保留整行的前部描述供安全分类。
                    product_name = ''
                    candidate_cells = tr.select('.td-z1-sp2-kc')
                    for cell in candidate_cells:
                        cell_text = " ".join(cell.stripped_strings).strip()
                        if not cell_text:
                            continue
                        if 'Contract extension possible from' in cell_text:
                            continue
                        if cell_text == server_id_text:
                            continue
                        if len(cell_text) <= 160:
                            product_name = cell_text
                            break
                    if not product_name:
                        product_name = row_text[:160]
                    self._remember_contract_meta(server_id_text, product_name, row_text)

                    action_container = tr.select_one('.td-z1-sp2-kc .kc2_order_action_container')
                    if action_container:
                        action_text = action_container.get_text(" ", strip=True)
                    else:
                        action_cells = tr.select('.td-z1-sp2-kc')
                        action_text = action_cells[-1].get_text(" ", strip=True) if action_cells else ''

                    can_renew = True
                    can_renew_date = ''
                    if "Contract extension possible from" in action_text:
                        date_match = re.search(r'\b(\d{4}-\d{2}-\d{2})\b', action_text)
                        if date_match:
                            can_renew_date = date_match.group(1)
                            can_renew = (
                                datetime.today().date()
                                >= datetime.strptime(can_renew_date, "%Y-%m-%d").date()
                            )
                        else:
                            can_renew = False

                    servers[server_id_text] = (can_renew, can_renew_date)

                # 2) 新版 Notifications 手动续期警告
                fallback_ids = set(re.findall(r'\bContract:\s*(\d{4,10})\b', plain, re.I))

                for tr in soup.find_all('tr'):
                    row_text = " ".join(tr.stripped_strings)
                    m = warning_re.search(row_text)
                    if not m:
                        continue
                    order_id = self._extract_order_id_from_container(tr, fallback_ids)
                    if not order_id:
                        continue
                    deactivation_date = m.group(1)
                    product_name = ''
                    # 新版通知行常见格式：<合同号> <产品名> The service will be automatically...
                    prod_match = re.search(
                        rf'\b{re.escape(str(order_id))}\b\s+(.+?)\s+The service will be automatically',
                        row_text,
                        re.I
                    )
                    if prod_match:
                        product_name = prod_match.group(1).strip()
                    if not product_name:
                        product_name = row_text[:180]
                    self._remember_contract_meta(str(order_id), product_name, row_text)

                    servers[str(order_id)] = (True, deactivation_date)
                    logger.info(
                        f"⚠️ 合同 {order_id} 显示手动续期警告"
                        f"（当前停用日期: {deactivation_date}）"
                    )

                # 3) 通知不是 tr 的布局
                for link in soup.find_all('a'):
                    if 'extend contract' not in link.get_text(" ", strip=True).lower():
                        continue
                    container = link.find_parent(['tr', 'div', 'section', 'li']) or link.parent
                    if container is None:
                        continue
                    container_text = " ".join(container.stripped_strings)
                    m = warning_re.search(container_text)
                    if not m:
                        continue
                    order_id = self._extract_order_id_from_container(container, fallback_ids)
                    if not order_id:
                        continue
                    product_name = ''
                    prod_match = re.search(
                        rf'\b{re.escape(str(order_id))}\b\s+(.+?)\s+The service will be automatically',
                        container_text,
                        re.I
                    )
                    if prod_match:
                        product_name = prod_match.group(1).strip()
                    if not product_name:
                        product_name = container_text[:180]
                    self._remember_contract_meta(str(order_id), product_name, container_text)
                    servers[str(order_id)] = (True, m.group(1))

                if servers:
                    logger.info(f"第 {page_index} 个页面已解析到合同")

            if servers:
                logger.info(f"✅ 账号 {self.config.email} 找到 {len(servers)} 个合同")
            else:
                # 输出无敏感信息的结构诊断，便于下一轮定位真实导航。
                last_soup = BeautifulSoup(pages[-1].text, 'html.parser')
                captions = []
                for tag in last_soup.find_all(['a', 'div', 'button']):
                    text_label = tag.get_text(" ", strip=True)
                    if any(k in text_label.lower() for k in ('contract', 'vserver', 'notification')):
                        if text_label and len(text_label) < 120:
                            captions.append(text_label)
                logger.error(
                    "❌ 已尝试 Contracts 导航但仍未解析到合同；"
                    f"页面可见相关标签: {list(dict.fromkeys(captions))[:12]}"
                )
            return servers

        except Exception as e:
            logger.error(f"❌ 获取服务器列表失败: {e}", exc_info=True)
            return {}

    def renew_server(self, order_id: str) -> bool:
        """续期服务器，并以控制面板实际状态变化作为唯一成功标准。"""
        logger.info(f"正在续期服务器 {order_id}...")

        url = "https://support.euserv.com/index.iphp"
        headers = {
            'user-agent': USER_AGENT,
            'Host': 'support.euserv.com',
            'origin': 'https://support.euserv.com',
            'Referer': 'https://support.euserv.com/index.iphp'
        }

        try:
            before_state, before_date = self._get_manual_extension_state(order_id)
            logger.info(
                f"续期前面板状态: {before_state}"
                + (f"，停用日期 {before_date}" if before_date else "")
            )

            # 步骤1: 打开合同详情
            data = {
                'Submit': 'Extend contract',
                'sess_id': self.sess_id,
                'ord_no': order_id,
                'subaction': 'choose_order',
                'show_contract_extension': '1',
                'choose_order_subaction': 'show_contract_details'
            }
            resp1 = self.session.post(url, headers=headers, data=data, timeout=30)
            resp1.raise_for_status()

            # 步骤1.5: 新版面板会先打开 change-plan / manual-extension 对话框
            data = {
                'sess_id': self.sess_id,
                'subaction': 'kc2_customer_contract_details_get_change_plan_dialog',
                'ord_id': order_id,
                'show_manual_extension_if_available': '1',
            }
            resp_plan = self.session.post(url, headers=headers, data=data, timeout=30)
            resp_plan.raise_for_status()

            # 步骤2: 触发安全验证 PIN
            data = {
                'sess_id': self.sess_id,
                'subaction': 'show_kc2_security_password_dialog',
                'prefix': 'kc2_customer_contract_details_extend_contract_',
                'type': '1'
            }
            resp2 = self.session.post(url, headers=headers, data=data, timeout=30)
            resp2.raise_for_status()

            pin_prompt = resp2.text.lower()
            if not any(marker in pin_prompt for marker in (
                'pin sent to', 'enter pin', 'security_password_dialog',
                'kc2_security_password_dialog_prompt'
            )):
                logger.error(
                    "❌ EUserv 未返回 PIN 验证对话框，停止续期，避免误判成功。"
                    f"响应摘要: {re.sub(r'\\s+', ' ', resp2.text)[:300]}"
                )
                return False

            security_raw = resp2.text or ''
            security_text = BeautifulSoup(security_raw, 'html.parser').get_text(" ", strip=True).lower()
            totp_secret = os.getenv("EUSERV_TOTP_SECRET", "").strip()

            # 登录与续期使用的是两套验证机制：
            # 登录可要求 Authenticator；续期 token 接口实测要求邮件 PIN。
            # 只有续期对话框明确写出 Authenticator 时才使用 TOTP。
            renewal_uses_authenticator = any(marker in security_text for marker in (
                'authenticator app',
                'shown in your authenticator',
                'shown in yout authenticator',
                'two-factor authentication',
                '2fa'
            ))

            # 步骤3: 获取安全 PIN（已配置 Authenticator 时直接使用 TOTP）
            if renewal_uses_authenticator:
                logger.info("🔐 续期安全检查使用 Authenticator 动态 PIN")
                if not totp_secret:
                    logger.error("❌ 未配置 EUSERV_TOTP_SECRET，无法完成续期安全验证")
                    return False
                pin = generate_totp(totp_secret)
                if not pin:
                    logger.error("❌ 无法生成续期 Authenticator TOTP")
                    return False
                logger.info("✅ 已生成续期 Authenticator 动态 PIN")
            else:
                logger.info("📧 续期安全检查要求邮箱 PIN")
                time.sleep(10)
                pin = get_euserv_pin(
                    self.config.email_pin,
                    self.config.email_password,
                    self.config.imap_server,
                    max_retries=3,
                    retry_interval=4,
                    max_age_seconds=120
                )
                if not pin:
                    logger.error("❌ 获取续期 PIN 码失败")
                    return False

            # 步骤4: PIN 换 token
            data = {
                'sess_id': self.sess_id,
                'auth': pin,
                'subaction': 'kc2_security_password_get_token',
                'prefix': 'kc2_customer_contract_details_extend_contract_',
                'type': '1',
                'ident': 'kc2_customer_contract_details_extend_contract_' + order_id
            }
            resp3 = self.session.post(url, headers=headers, data=data, timeout=30)
            resp3.raise_for_status()

            try:
                token_result = resp3.json()
            except ValueError:
                logger.error(
                    "❌ token 接口返回非 JSON: "
                    + re.sub(r'\s+', ' ', resp3.text)[:300]
                )
                return False

            if token_result.get('rs') != 'success':
                logger.error(f"❌ 获取 token 失败: {token_result.get('rs', 'unknown')}")
                return False

            token = (token_result.get('token') or {}).get('value')
            if not token:
                logger.error("❌ token 响应缺少 token.value")
                return False

            # 步骤5: 获取最终续期确认框，并转发隐藏字段
            data = {
                'sess_id': self.sess_id,
                'subaction': 'kc2_customer_contract_details_get_extend_contract_confirmation_dialog',
                'token': token
            }
            resp4 = self.session.post(url, headers=headers, data=data, timeout=30)
            resp4.raise_for_status()

            dialog_html = resp4.text
            try:
                dialog_json = resp4.json()
                inner = dialog_json.get('html')
                if isinstance(inner, dict):
                    inner = inner.get('value')
                if isinstance(inner, str):
                    dialog_html = inner
            except ValueError:
                pass

            if 'captcha' in dialog_html.lower() or 'securimage' in dialog_html.lower():
                logger.error("❌ 最终续期确认框要求额外图形验证码，当前流程停止")
                return False

            extra_fields = {}
            dialog_soup = BeautifulSoup(dialog_html, 'html.parser')
            for inp in dialog_soup.find_all('input'):
                name = inp.get('name')
                if not name:
                    continue
                input_type = (inp.get('type') or '').lower()
                if input_type == 'hidden':
                    extra_fields[name] = inp.get('value', '')
                elif input_type == 'checkbox' and inp.has_attr('checked'):
                    extra_fields[name] = inp.get('value', '1')

            for key in ('sess_id', 'subaction', 'token', 'ord_id'):
                extra_fields.pop(key, None)

            # 步骤6: 正式提交续期
            data = {
                'sess_id': self.sess_id,
                'ord_id': order_id,
                'subaction': 'kc2_customer_contract_details_extend_contract_term',
                'token': token
            }
            data.update(extra_fields)

            resp5 = self.session.post(url, headers=headers, data=data, timeout=30)
            resp5.raise_for_status()

            response_text = resp5.text or ''
            response_plain = re.sub(r'<[^>]+>', ' ', response_text)
            response_plain = re.sub(r'\s+', ' ', response_plain).strip()

            # EUserv 最终提交接口经常直接返回整页控制面板 HTML。
            # 不能因为 HTML/JS 内出现 "error" 等通用单词就判失败。
            # 仅识别明确的结构化失败响应；最终成功与否一律以下一步后台状态复核为准。
            structured_failure = False
            try:
                submit_json = resp5.json()
                rs = str(submit_json.get('rs', '')).strip().lower()
                status = str(submit_json.get('status', '')).strip().lower()
                message = str(
                    submit_json.get('error')
                    or submit_json.get('message')
                    or submit_json.get('msg')
                    or ''
                ).strip()
                if rs and rs not in ('success', 'ok', '1', 'true'):
                    structured_failure = True
                if status in ('error', 'failed', 'failure', 'invalid'):
                    structured_failure = True
                if structured_failure:
                    logger.warning(
                        "续期提交接口返回结构化失败，仍将通过后台状态进行最终复核: "
                        + (message[:300] if message else str(submit_json)[:300])
                    )
            except ValueError:
                # HTML 返回是 EUserv 的正常行为之一。
                logger.info("续期提交接口返回控制面板 HTML，进入后台状态复核")

            # 步骤7: 事实校验。只有后台警告消失或停用日期后移才算成功。
            logger.info("正在验证 EUserv 后台是否真正完成续期...")
            for verify_attempt in range(1, 11):
                time.sleep(6)
                state, after_date = self._get_manual_extension_state(order_id)
                logger.info(
                    f"续期验证 {verify_attempt}/10: 状态={state}"
                    + (f"，停用日期={after_date}" if after_date else "")
                )

                if before_state == 'required' and state == 'clear':
                    logger.info(
                        f"✅ 合同 {order_id} 的手动续期/停用警告已从控制面板消失，续期确认成功"
                    )
                    return True

                if (
                    before_state == 'required'
                    and before_date
                    and state == 'required'
                    and after_date
                ):
                    try:
                        before_dt = datetime.strptime(before_date, "%Y-%m-%d").date()
                        after_dt = datetime.strptime(after_date, "%Y-%m-%d").date()
                        if after_dt > before_dt:
                            logger.info(
                                f"✅ 合同 {order_id} 停用日期已后移 "
                                f"{before_date} → {after_date}，续期确认成功"
                            )
                            return True
                    except ValueError:
                        pass

                # 兼容旧合同表：续期后会显示未来的 "Contract extension possible from"
                servers_after = self.get_servers()
                if order_id in servers_after:
                    can_renew_after, new_date = servers_after[order_id]
                    if not can_renew_after and new_date:
                        logger.info(
                            f"✅ 合同 {order_id} 已进入不可续期等待期"
                            f"（下次可续期: {new_date}），续期确认成功"
                        )
                        return True

            logger.error(
                f"❌ 合同 {order_id} 提交后控制面板状态未发生可验证的续期变化；"
                "本次严格判定为续期失败"
            )
            return False

        except Exception as e:
            logger.error(f"❌ 服务器 {order_id} 续期失败: {e}", exc_info=True)
            return False



def send_bark(title: str, content: str, config: GlobalConfig):
    """
    发送 Bark 推送通知
    
    Args:
        title: 推送标题
        content: 推送内容
        config: 全局配置对象
    """
    if not config.bark_url:
        logger.warning("⚠️ 未配置 Bark URL，跳过 Bark 通知")
        return
    
    try:
        post_url = config.bark_url.rstrip('/')
        data = {
            "title": title,
            "body": content,
            "sound": "telegraph",  # 推送音效
            "group": "EUserv",     # 分组
            "icon": "https://www.euserv.com/favicon.ico"  # 自定义图标
        }
        
        # 发送请求
        response = requests.post(post_url, json=data, timeout=20)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('code') == 200:
                logger.info("✅ Bark 推送发送成功")
            else:
                logger.error(f"❌ Bark 推送失败: {result.get('message', '未知错误')}")
        else:
            logger.error(f"❌ Bark 推送失败: HTTP {response.status_code}")
            
    except Exception as e:
        logger.error(f"❌ Bark 推送异常: {e}", exc_info=True)



def send_telegram(message: str, config: GlobalConfig):
    """发送 Telegram 通知：支持 Actions 按钮、关闭预览、失败重试和详细错误日志。"""
    if not config.telegram_bot_token or not config.telegram_chat_id:
        logger.warning("⚠️ 未配置 Telegram，跳过通知")
        return False

    url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"

    if len(message) > 3900:
        message = message[:3850] + "\n\n<i>…消息过长，已截断，请查看 Actions 日志。</i>"

    data = {
        "chat_id": config.telegram_chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    server_url = os.getenv("GITHUB_SERVER_URL", "").rstrip("/")
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    run_id = os.getenv("GITHUB_RUN_ID", "").strip()
    if server_url and repository and run_id:
        data["reply_markup"] = {
            "inline_keyboard": [[{
                "text": "查看 GitHub Actions",
                "url": f"{server_url}/{repository}/actions/runs/{run_id}"
            }]]
        }

    last_error = None
    for attempt in range(1, 3):
        try:
            response = requests.post(url, json=data, timeout=15)
            try:
                payload = response.json()
            except ValueError:
                payload = {}

            if response.status_code == 200 and payload.get("ok") is True:
                logger.info("✅ Telegram 通知发送成功")
                return True

            description = payload.get("description") or response.text[:300]
            last_error = f"HTTP {response.status_code}: {description}"
            logger.warning(f"⚠️ Telegram 通知第 {attempt}/2 次失败: {last_error}")
        except Exception as e:
            last_error = str(e)
            logger.warning(f"⚠️ Telegram 通知第 {attempt}/2 次异常: {last_error}")

        if attempt < 2:
            time.sleep(2)

    logger.error(f"❌ Telegram 通知最终发送失败: {last_error or '未知错误'}")
    return False


def send_notification(title: str, message: str, config: GlobalConfig):
    """
    统一发送通知（支持 Telegram 和 Bark）
    
    Args:
        title: 通知标题（主要用于 Bark）
        message: 通知内容
        config: 全局配置对象
    """
    # 发送 Telegram 通知
    send_telegram(message, config)
    
    # 发送 Bark 通知（将 HTML 格式转为纯文本）
    plain_message = re.sub(r'<[^>]+>', '', message)  # 移除 HTML 标签
    send_bark(title, plain_message, config)


def process_account(account_config: AccountConfig, global_config: GlobalConfig) -> Dict:
    """处理单个账号的续期任务"""
    result = {
        'email': account_config.email,
        'success': False,
        'servers': {},
        'server_meta': {},
        'renew_results': [],
        'paid_reminders': [],
        'error': None,
        'error_type': None,   # 'login' | 'get_servers' | 'exception'
    }
    
    try:
        euserv = EUserv(account_config)
        
        # 登录（最多重试）
        login_success = False
        for attempt in range(global_config.max_login_retries):
            if attempt > 0:
                logger.info(f"账号 {account_config.email} 第 {attempt + 1} 次登录尝试...")
                time.sleep(5)
            
            if euserv.login():
                login_success = True
                break
        
        if not login_success:
            result['error'] = "登录失败"
            result['error_type'] = 'login'
            return result
        
        # 更新用户信息（不影响续期主流程）
        if not euserv.update_info():
            logger.warning(f"⚠️ 账号 {account_config.email} 更新用户信息失败，续期流程继续")

        # 获取服务器列表
        servers = euserv.get_servers()
        result['servers'] = servers
        result['server_meta'] = dict(euserv.server_meta)
        
        if not servers:
            result['error'] = "未找到任何服务器"
            result['error_type'] = 'get_servers'
            result['success'] = False
            return result
        
        # 检查并续期：只有明确识别为 FREE 的合同才自动执行。
        for order_id, (can_renew, can_renew_date) in servers.items():
            logger.info(f"检查服务器: {order_id}")
            meta = euserv.server_meta.get(str(order_id), {})
            product_name = meta.get('product_name', '未知产品')
            is_free = bool(meta.get('is_free'))
            whitelist_ok = (
                not AUTO_RENEW_CONTRACTS
                or str(order_id) in AUTO_RENEW_CONTRACTS
            )

            if can_renew:
                if is_free and whitelist_ok:
                    logger.info(
                        f"⏰ FREE 合同 {order_id} 可以续期，将自动执行 "
                        f"({product_name})"
                    )
                    if euserv.renew_server(order_id):
                        verified_servers = euserv.get_servers()
                        verified_state = verified_servers.get(order_id)
                        next_renew_date = ''
                        if verified_state:
                            _, next_renew_date = verified_state

                        result['renew_results'].append({
                            'order_id': order_id,
                            'success': True,
                            'product_name': product_name,
                            'previous_date': can_renew_date,
                            'next_renew_date': next_renew_date,
                            'message': f"✅ FREE 服务器 {order_id} 续期成功"
                        })
                    else:
                        result['renew_results'].append({
                            'order_id': order_id,
                            'success': False,
                            'product_name': product_name,
                            'previous_date': can_renew_date,
                            'next_renew_date': '',
                            'message': f"❌ FREE 服务器 {order_id} 续期失败"
                        })
                else:
                    if is_free and not whitelist_ok:
                        reminder_type = 'free_not_whitelisted'
                        reminder_message = 'FREE 合同不在自动续期白名单，仅提醒未操作'
                        logger.warning(
                            f"🛡️ FREE 合同 {order_id} 不在 AUTO_RENEW_CONTRACTS 白名单，"
                            f"仅提醒、不自动操作 ({product_name})"
                        )
                    else:
                        reminder_type = 'paid_or_unknown'
                        reminder_message = '付费或未知类型合同已到可续期阶段，仅提醒未操作'
                        logger.warning(
                            f"💳 合同 {order_id} 可续期，但不是明确 FREE 产品，"
                            f"仅提醒、不自动操作 ({product_name})"
                        )

                    result['paid_reminders'].append({
                        'order_id': order_id,
                        'product_name': product_name,
                        'renew_date': can_renew_date,
                        'reminder_type': reminder_type,
                        'message': reminder_message
                    })
            else:
                logger.info(
                    f"✓ 服务器 {order_id} 暂不需要续期"
                    f"（可续期日期: {can_renew_date or '未知'}；产品: {product_name}）"
                )

        result['success'] = all(item.get('success', False) for item in result['renew_results']) if result['renew_results'] else True
        if result['renew_results'] and not result['success']:
            result['error'] = "至少一个合同续期未通过后台状态验证"
            result['error_type'] = 'renew'
        
    except Exception as e:
        logger.error(f"处理账号 {account_config.email} 时发生异常: {e}", exc_info=True)
        result['error'] = str(e)
        result['error_type'] = 'exception'
    
    return result


def main():
    """主函数"""
    logger.info("=" * 60)
    logger.info("EUserv 多账号自动续期脚本（多线程版本）")
    logger.info(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"配置账号数: {len(ACCOUNTS)}")
    logger.info(f"最大并发线程: {GLOBAL_CONFIG.max_workers}")
    if AUTO_RENEW_CONTRACTS:
        logger.info("自动续期合同白名单已启用")
    else:
        logger.warning(
            "⚠️ 未配置 AUTO_RENEW_CONTRACTS；仍只自动续期明确 FREE 产品，"
            "建议增加合同号白名单作为第二道保险"
        )
    logger.info(f"人工处理提醒去重间隔: {PAID_REMINDER_INTERVAL_DAYS} 天")
    logger.info("=" * 60)
    
    if not ACCOUNTS:
        logger.error("❌ 未配置任何账号")
        sys.exit(1)
    
    # 使用线程池处理多个账号
    all_results = []
    with ThreadPoolExecutor(max_workers=GLOBAL_CONFIG.max_workers) as executor:
        # 提交所有任务
        future_to_account = {
            executor.submit(process_account, account, GLOBAL_CONFIG): account 
            for account in ACCOUNTS
            if account.email and str(account.email).strip() and account.password and str(account.password).strip() and account.email_password and str(account.email_password).strip()
        }
        
        # 等待任务完成
        for future in as_completed(future_to_account):
            account = future_to_account[future]
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                logger.error(f"处理账号 {account.email} 时发生未预期的异常: {e}", exc_info=True)
                all_results.append({
                    'email': account.email,
                    'success': False,
                    'error': f"未预期的异常: {str(e)}"
                })
    
    # 生成汇总报告 & 按需通知
    logger.info("\n" + "=" * 60)
    logger.info("处理结果汇总")
    logger.info("=" * 60)

    notify_parts = []
    renew_success_count = 0
    renew_failure_count = 0
    system_failure_count = 0
    manual_reminder_count = 0
    notification_state = load_notification_state()
    notification_state_changed = False
    time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    for result in all_results:
        email = result['email']
        safe_email = escape(str(email))
        logger.info(f"\n账号: {email}")

        if not result['success']:
            error_type = result.get('error_type', 'exception')
            error_msg = result.get('error', '未知错误')
            safe_error = escape(str(error_msg))
            logger.error(f"  ❌ 处理失败: {error_msg}")

            if error_type == 'renew':
                failed_renewals = [
                    rr for rr in result.get('renew_results', [])
                    if not rr.get('success')
                ]
                if failed_renewals:
                    for rr in failed_renewals:
                        renew_failure_count += 1
                        order_id = escape(str(rr.get('order_id', '未知')))
                        notify_parts.append(
                            f"<b>❌ 续期失败</b>\n"
                            f"📧 账号：<code>{safe_email}</code>\n"
                            f"📄 合同：<code>{order_id}</code>\n"
                            f"⚠️ 状态：后台续期结果未通过验证"
                        )
                else:
                    renew_failure_count += 1
                    notify_parts.append(
                        f"<b>❌ 续期失败</b>\n"
                        f"📧 账号：<code>{safe_email}</code>\n"
                        f"⚠️ 原因：{safe_error}"
                    )
            else:
                system_failure_count += 1
                if error_type == 'login':
                    label = "登录失败"
                elif error_type == 'get_servers':
                    label = "合同读取失败"
                else:
                    label = "运行异常"

                notify_parts.append(
                    f"<b>❌ {label}</b>\n"
                    f"📧 账号：<code>{safe_email}</code>\n"
                    f"⚠️ 原因：{safe_error}"
                )
            continue

        servers = result.get('servers', {})
        logger.info(f"  服务器数量: {len(servers)}")

        paid_reminders = result.get('paid_reminders', [])
        for reminder in paid_reminders:
            raw_order_id = str(reminder.get('order_id', '未知'))
            if not should_send_manual_reminder(
                notification_state, email, raw_order_id
            ):
                logger.info(
                    f"🔕 合同 {raw_order_id} 人工处理提醒已在 "
                    f"{PAID_REMINDER_INTERVAL_DAYS} 天内发送过，本次不重复发送"
                )
                continue

            order_id = escape(raw_order_id)
            product_name = escape(str(reminder.get('product_name', '未知产品')))
            renew_date = escape(str(reminder.get('renew_date') or '当前已可续期'))
            reminder_type = reminder.get('reminder_type', 'paid_or_unknown')

            if reminder_type == 'free_not_whitelisted':
                block_title = "🛡️ FREE 合同白名单提醒"
                action_text = "未自动续期；请确认 AUTO_RENEW_CONTRACTS 白名单"
            else:
                block_title = "💳 付费合同续期提醒"
                action_text = "未自动续期；请手动确认是否续费"

            notify_parts.append(
                f"<b>{block_title}</b>\n"
                f"📧 账号：<code>{safe_email}</code>\n"
                f"📄 合同：<code>{order_id}</code>\n"
                f"📦 产品：{product_name}\n"
                f"📅 状态：{renew_date}\n"
                f"🛑 操作：{action_text}"
            )
            manual_reminder_count += 1
            mark_manual_reminder_sent(notification_state, email, raw_order_id)
            notification_state_changed = True

        renew_results = result.get('renew_results', [])
        if renew_results:
            logger.info(f"  续期操作: {len(renew_results)} 个")
            for rr in renew_results:
                logger.info(f"    {rr['message']}")
                order_id = escape(str(rr.get('order_id', '未知')))
                product_name = escape(str(rr.get('product_name', '未知产品')))

                if rr.get('success'):
                    renew_success_count += 1
                    next_date = rr.get('next_renew_date') or '已续期，等待下次检查'
                    safe_next_date = escape(str(next_date))
                    notify_parts.append(
                        f"<b>✅ 续期成功</b>\n"
                        f"📧 账号：<code>{safe_email}</code>\n"
                        f"📄 合同：<code>{order_id}</code>\n"
                        f"📦 产品：{product_name}\n"
                        f"📅 下次可续期：<b>{safe_next_date}</b>\n"
                        f"🔎 验证：EUserv 后台状态已更新"
                    )
                else:
                    renew_failure_count += 1
                    notify_parts.append(
                        f"<b>❌ 续期失败</b>\n"
                        f"📧 账号：<code>{safe_email}</code>\n"
                        f"📄 合同：<code>{order_id}</code>\n"
                        f"📦 产品：{product_name}\n"
                        f"⚠️ 状态：后台状态未发生可验证变化"
                    )
        else:
            logger.info("  ✓ 所有服务器均无需续期")
            for order_id, (can_renew, can_renew_date) in servers.items():
                if can_renew_date:
                    logger.info(f"    订单 {order_id}: 可续期日期 {can_renew_date}")

    if notify_parts:
        has_error = (renew_failure_count + system_failure_count) > 0
        paid_reminder_count = manual_reminder_count
        if has_error:
            header_icon = "❌"
            header_text = "EUserv 自动续期异常"
            notification_title = "EUserv 自动续期异常"
        elif renew_success_count > 0:
            header_icon = "✅"
            header_text = "EUserv 自动续期成功"
            notification_title = "EUserv 自动续期成功"
        else:
            header_icon = "💳"
            header_text = "EUserv 付费合同提醒"
            notification_title = "EUserv 付费合同提醒"

        summary_bits = []
        if renew_success_count:
            summary_bits.append(f"成功 {renew_success_count}")
        if renew_failure_count:
            summary_bits.append(f"续期失败 {renew_failure_count}")
        if system_failure_count:
            summary_bits.append(f"运行异常 {system_failure_count}")
        if paid_reminder_count:
            summary_bits.append(f"付费提醒 {paid_reminder_count}")

        summary_text = " · ".join(summary_bits) if summary_bits else "状态更新"
        header = (
            f"<b>{header_icon} {header_text}</b>\n"
            f"📊 {summary_text}\n"
            f"🕒 {escape(time_str)}"
        )
        message = header + "\n\n" + "\n\n".join(notify_parts)
        send_notification(notification_title, message, GLOBAL_CONFIG)
    else:
        logger.info("✅ 本次无 FREE 续期操作，且无人工处理提醒")

    if notification_state_changed:
        save_notification_state(notification_state)
        logger.info("💾 已更新人工提醒去重状态")

    logger.info("\n" + "=" * 60)
    logger.info("执行完成")
    logger.info("=" * 60)
    has_failure = any(not r.get("success", False) for r in all_results)
    sys.exit(1 if has_failure else 0)


if __name__ == "__main__":
    main()