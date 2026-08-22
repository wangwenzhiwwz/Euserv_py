#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility runner for EUserv order pages whose tab markup changed."""
import re
from datetime import datetime
from bs4 import BeautifulSoup
import euser_renew as app


def _parse_orders(html):
    soup = BeautifulSoup(html, "html.parser")
    servers = {}
    # EUserv may now render order rows outside the old kc2_order_customer_orders_tab_content_* containers.
    for tr in soup.select("tr"):
        text = " ".join(tr.stripped_strings)
        if not text:
            continue
        ids = []
        for tag in tr.select("[name='ord_no'], [name='ord_id']"):
            if tag.get("value"):
                ids.append(tag["value"].strip())
        for tag in tr.select("[data-ord-no], [data-order-id], [data-ord-id]"):
            for attr in ("data-ord-no", "data-order-id", "data-ord-id"):
                if tag.get(attr):
                    ids.append(tag[attr].strip())
        for tag in tr.select("a[href], button[onclick], input[onclick]"):
            blob = " ".join([tag.get("href", ""), tag.get("onclick", ""), str(tag)])
            ids += re.findall(r"(?:ord_no|ord_id|order_id)\D{0,8}(\d{4,})", blob, re.I)
        if not ids:
            # Fallback: old layout keeps the order number in this cell.
            cell = tr.select_one(".td-z1-sp1-kc")
            if cell:
                candidate = cell.get_text(" ", strip=True)
                if re.fullmatch(r"\d{4,}", candidate):
                    ids.append(candidate)
        if not ids:
            continue
        date_match = re.search(r"Contract extension possible from\s*(?:[^0-9]{0,20})?(\d{4}-\d{2}-\d{2})", text, re.I)
        can_renew_date = date_match.group(1) if date_match else ""
        can_renew = True
        if can_renew_date:
            can_renew = datetime.today().date() >= datetime.strptime(can_renew_date, "%Y-%m-%d").date()
        for order_id in ids:
            if order_id:
                servers[str(order_id)] = (can_renew, can_renew_date)
    return servers


def fixed_get_servers(self):
    app.logger.info(f"正在获取账号 {self.config.email} 的服务器列表...")
    if not self.sess_id:
        app.logger.error("❌ 未登录")
        return {}
    headers = {
        "user-agent": app.USER_AGENT,
        "referer": f"https://support.euserv.com/index.iphp?sess_id={self.sess_id}",
        "x-requested-with": "XMLHttpRequest",
    }
    attempts = [
        ("GET", {"sess_id": self.sess_id}),
        ("GET", {"sess_id": self.sess_id, "subaction": "show_kwk_main"}),
        ("GET", {"sess_id": self.sess_id, "action": "show_customer_orders"}),
    ]
    last_error = None
    for index, (method, params) in enumerate(attempts, 1):
        try:
            app.logger.info(f"订单页读取尝试 {index}/{len(attempts)}: {params}")
            resp = self.session.get("https://support.euserv.com/index.iphp", headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            servers = _parse_orders(resp.text)
            soup = BeautifulSoup(resp.text, "html.parser")
            row_count = len(soup.select("tr"))
            tab_count = len(soup.select("[id*='order'], [class*='order']"))
            app.logger.info(f"订单页诊断: 尝试={index}, 页面行={row_count}, 订单相关节点={tab_count}, 识别订单={len(servers)}")
            if servers:
                app.logger.info(f"✅ 账号 {self.config.email} 找到 {len(servers)} 台服务器")
                return servers
            last_error = f"尝试 {index} 未发现订单"
        except Exception as exc:
            last_error = str(exc)
            app.logger.warning(f"订单页读取尝试 {index} 失败: {exc}")
    app.logger.error(f"❌ 未找到任何服务器: {last_error or '未知原因'}")
    return {}


app.EUserv.get_servers = fixed_get_servers
app.main()
