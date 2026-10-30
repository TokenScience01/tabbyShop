"""Manual listings using the public client's settings, quote and list protocol."""
from decimal import Decimal, InvalidOperation
import re

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QLabel, QLineEdit, QComboBox,
                               QPushButton, QHBoxLayout)


PRICE_PATTERN = re.compile(r'^(0|[1-9][0-9]{0,11})(\.[0-9]{1,8})?$')
SINGLE_RESOURCES = {'BOSS_ENTRY_TICKET', 'ATONEMENT_STONE', 'TREASURE_STONE'}
ITEM_CODES = {'WOODEN_FISHING_ROD', 'FISHPOND_NFT', 'MARS'}
SLOTS = {'WEAPON', 'HAT', 'ARMOR', 'SHOES', 'RING', 'AMULET'}


def valid_price(value, minimum):
    try:
        floor = Decimal(str(minimum))
        return bool(PRICE_PATTERN.fullmatch(value) and floor.is_finite() and floor > 0
                    and Decimal(value) >= floor)
    except (InvalidOperation, ValueError, TypeError):
        return False


def listing_key(item):
    code = str(item.get('itemCode', '')).upper()
    if code == 'TOWN_STONE':
        return ('stone', str(item.get('stoneId')))
    if code in SINGLE_RESOURCES or code == 'HEALTH_POTION':
        return ('resource', code)
    return ('item', str(item.get('playerItemId')))


def listing_payload(item, quantity, price, fee_percent):
    """Reject unsupported or unavailable inventory before constructing a mutation."""
    code = str(item.get('itemCode', '')).upper()
    if any(item.get(flag) for flag in ('locked', 'listed', 'marketListed', 'isLocked', 'isListed')):
        raise ValueError('该物品已锁定或已上架，请刷新背包。')
    if code == 'STAMINA_POTION':
        raise ValueError('体力恢复药水不可上架。')
    body = {'price': price, 'feePercent': fee_percent}
    if code == 'HEALTH_POTION':
        if quantity not in (10, 20, 30, 40, 50) or quantity > int(item.get('quantity', 0)):
            raise ValueError('生命药水每组 10–50 瓶，数量须为 10 的倍数且不超过库存。')
        return dict(body, itemKind=code, quantity=quantity)
    if quantity != 1:
        raise ValueError('该类型每次仅上架 1 件。')
    if code in SINGLE_RESOURCES:
        if int(item.get('quantity', 0)) < 1:
            raise ValueError('库存不足。')
        return dict(body, itemKind=code, quantity=1)
    if code == 'TOWN_STONE':
        if not isinstance(item.get('stoneId'), int) or isinstance(item['stoneId'], bool) or item['stoneId'] <= 0:
            raise ValueError('缺少有效回城石 ID，请刷新背包。')
        return dict(body, itemKind=code, stoneId=item['stoneId'], quantity=1)
    if code not in ITEM_CODES and str(item.get('slotType', '')).upper() not in SLOTS:
        raise ValueError('该道具尚无已确认的上架协议。')
    item_id = item.get('playerItemId')
    if not isinstance(item_id, int) or isinstance(item_id, bool) or item_id <= 0:
        raise ValueError('缺少有效物品 ID，请刷新背包。')
    return dict(body, playerItemId=item_id)


class MarketListingDialog(QDialog):
    def __init__(self, owner, item, name):
        super().__init__(owner)
        self.owner = owner
        self.item = dict(item)
        self.session = owner._login_generation
        self.token = owner.get_session_token()
        self.minimum = None
        self.quote = None
        self.quote_price = None
        self.busy = False
        self.completed = False
        self.uncertain = False
        self.setWindowTitle('上架出售 · TABBY')
        self.resize(460, 380)
        layout = QVBoxLayout(self)
        title = QLabel(f"{name} · ID {item.get('stoneId', item.get('playerItemId', '资源'))}")
        title.setWordWrap(True)
        layout.addWidget(title)
        note = QLabel('装备上架后会被卸下并锁定；道具数量会被预留至成交或下架。回城石上架期间仍会到期。')
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addWidget(QLabel('上架数量'))
        self.quantity = QComboBox()
        counts = (10, 20, 30, 40, 50) if item.get('itemCode') == 'HEALTH_POTION' else (1,)
        for count in counts:
            if count <= int(item.get('quantity', 1)):
                self.quantity.addItem(str(count), count)
        layout.addWidget(self.quantity)
        layout.addWidget(QLabel('整组总价（TABBY，最多 8 位小数）'))
        self.price = QLineEdit()
        self.price.setMaxLength(21)
        self.price.setPlaceholderText('正在读取服务器最低价…')
        layout.addWidget(self.price)
        self.totals = QLabel('手续费 —\n预计到账 —')
        self.totals.setWordWrap(True)
        layout.addWidget(self.totals)
        self.message = QLabel('正在读取上架设置。')
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        buttons = QHBoxLayout()
        self.refresh = QPushButton('重新读取报价')
        self.confirm = QPushButton('确认上架')
        self.confirm.setEnabled(False)
        self.cancel = QPushButton('关闭')
        for button in (self.refresh, self.confirm, self.cancel):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.delay = QTimer(self)
        self.delay.setSingleShot(True)
        self.delay.setInterval(350)
        self.delay.timeout.connect(self.fetch_quote)
        self.price.textChanged.connect(self.invalidate_quote)
        self.quantity.currentIndexChanged.connect(self.invalidate_quote)
        self.refresh.clicked.connect(self.load_settings)
        self.confirm.clicked.connect(self.submit)
        self.cancel.clicked.connect(self.reject)

    def live(self):
        return (self.owner._login_generation == self.session and bool(self.token)
                and self.owner.get_session_token() == self.token and self.owner._listing_dialog is self)

    def load_settings(self):
        if self.busy or self.completed or self.uncertain or not self.live():
            return
        self.minimum = None
        self.invalidate_quote()
        self.owner.request_social_api('marketListingSettings', '/shop/listing-settings')

    def invalidate_quote(self, *_args):
        self.quote = None
        self.confirm.setEnabled(False)
        self.totals.setText('手续费 —\n预计到账 —')
        if not self.busy and not self.completed and not self.uncertain:
            self.delay.start()

    def fetch_quote(self):
        value = self.price.text().strip()
        if self.busy or self.completed or self.uncertain or not self.live():
            return
        if self.minimum is None:
            return
        if not valid_price(value, self.minimum):
            self.message.setText(f'最低 {self.minimum} TABBY，最多 12 位整数、8 位小数；不支持科学计数法。')
            return
        self.quote_price = value
        self.quote = None
        self.confirm.setEnabled(False)
        self.owner.request_social_api('marketListingQuote', '/shop/listing-quote', 'POST', {'price': value})
        self.message.setText('正在读取服务器手续费与到账报价…')

    def accept_response(self, key, data):
        if self.session != self.owner._login_generation:
            return
        result = data.get('socialApiResult', {})
        error = data.get('socialApiError')
        if key == 'marketListingSettings':
            try:
                minimum = Decimal(str(result['minimumPrice']))
                if not minimum.is_finite() or minimum <= 0:
                    raise ValueError()
            except (KeyError, TypeError, InvalidOperation, ValueError):
                self.message.setText('无法读取市场最低价，暂不可上架；可重新读取。')
                return
            if error:
                self.message.setText('市场暂不可用，请重新读取设置。')
                return
            self.minimum = str(minimum)
            self.price.setPlaceholderText(f'最低 {minimum} TABBY')
            self.message.setText(f'服务器最低价：{minimum} TABBY。')
            self.invalidate_quote()
        elif key == 'marketListingQuote':
            value = self.price.text().strip()
            if error or not isinstance(result, dict) or self.quote_price != value or str(result.get('price')) != value:
                self.message.setText('报价未确认或价格已变动，请重新获取。')
                return
            try:
                for field in ('feePercent', 'feeAmount', 'sellerAmount'):
                    amount = Decimal(str(result[field]))
                    if not amount.is_finite() or amount < 0:
                        raise ValueError()
                if Decimal(str(result['feeAmount'])) + Decimal(str(result['sellerAmount'])) != Decimal(value):
                    raise ValueError()
            except (KeyError, TypeError, InvalidOperation, ValueError):
                self.message.setText('服务器报价缺失或金额不一致，请重新读取。')
                return
            self.quote = dict(result)
            self.totals.setText(f"手续费 {result['feePercent']}% · {result['feeAmount']} TABBY\n预计到账 {result['sellerAmount']} TABBY")
            self.message.setText('请核对物品、数量和整组总价后确认上架。')
            self.confirm.setEnabled(valid_price(value, self.minimum) and self.quantity.currentData() is not None
                                    and not self.busy and not self.completed and not self.uncertain)
        elif key == 'marketListingSubmit':
            self.busy = False
            self.owner._listing_submit_pending = False
            self.cancel.setEnabled(True)
            if (not error and data.get('socialApiStatus', 200) == 200 and isinstance(result, dict)
                    and result.get('ok') is not False and not result.get('error') and not result.get('code')):
                self.completed = True
                self.owner.listing_confirmed(self.item, self.quantity.currentData())
                self.message.setText('服务器确认上架成功，正在刷新背包。')
                self.cancel.setText('完成')
            else:
                self.uncertain = True
                codes = {'listing_limit': '最多同时上架 10 件，请先下架或等待售出。',
                         'insufficient_potions': '生命药水库存不足。', 'insufficient_tickets': 'Boss 凭证库存不足。',
                         'insufficient_stones': '赎罪石库存不足。', 'insufficient_treasure_stones': '秘宝之石库存不足。'}
                detail = codes.get(str(result.get('code', '')) if isinstance(result, dict) else '', '')
                if detail and 400 <= data.get('socialApiStatus', 0) < 500:
                    self.uncertain = False
                    self.owner._listing_blocked.discard(listing_key(self.item))
                    for control in (self.price, self.quantity, self.refresh):
                        control.setEnabled(True)
                    self.quote = None
                    self.message.setText(detail + '请刷新库存并重新读取报价。')
                    self.owner.refresh_profile_data(force=True)
                    return
                self.message.setText(detail + '未确认上架成功；请核对背包及官网商城，不会自动重发该物品的上架请求。')
                self.owner.refresh_profile_data(force=True)

    def submit(self):
        value = self.price.text().strip()
        if (self.busy or self.completed or self.uncertain or not self.live() or self.owner._listing_submit_pending
                or self.owner.fishing_busy() or not self.quote or self.quote_price != value
                or str(self.quote.get('price')) != value or not valid_price(value, self.minimum)):
            return
        try:
            fresh = self.owner.current_listing_item(listing_key(self.item))
            if fresh is None:
                raise ValueError('物品已不在当前库存，请刷新背包。')
            body = listing_payload(fresh, self.quantity.currentData(), value, self.quote['feePercent'])
        except (ValueError, TypeError) as exc:
            self.message.setText(str(exc))
            return
        key = listing_key(self.item)
        if key in self.owner._listing_blocked:
            self.message.setText('该物品已有未核对的上架请求，请核对官网商城，勿重复提交。')
            return
        self.owner._listing_blocked.add(key)
        self.owner._listing_submit_pending = True
        self.busy = True
        self.delay.stop()
        for control in (self.confirm, self.cancel, self.price, self.quantity, self.refresh):
            control.setEnabled(False)
        self.owner.request_social_api('marketListingSubmit', '/shop/list', 'POST', body)
        self.message.setText('正在提交上架，等待服务器确认…')

    def reject(self):
        if self.busy and self.live():
            return
        self.delay.stop()
        super().reject()

    def closeEvent(self, event):
        if self.busy and self.live():
            event.ignore()
        else:
            self.delay.stop()
            super().closeEvent(event)
