import unittest

from game_client.market_listing import valid_price, listing_payload, listing_key


class ListingProtocolTests(unittest.TestCase):
    def test_prices_use_exact_decimal_limits(self):
        for value in ('100', '100.00000001', '999999999999.99999999'):
            self.assertTrue(valid_price(value, '100'))
        for value in ('99.99999999', '1e3', 'NaN', 'Infinity', '-100', '0100',
                      '100.000000001', '1000000000000', '100.', '', ' 100'):
            self.assertFalse(valid_price(value, '100'), value)
        for floor in ('NaN', 'Infinity', '-1', '0', None):
            self.assertFalse(valid_price('100', floor))

    def test_equipment_rod_nft_and_mars_use_real_item_id(self):
        for code in ('SWORDP1', 'WOODEN_FISHING_ROD', 'FISHPOND_NFT', 'MARS'):
            item = {'itemCode': code, 'playerItemId': 9, 'slotType': 'WEAPON' if code == 'SWORDP1' else 'OTHER'}
            self.assertEqual(listing_payload(item, 1, '100', '10'),
                             {'playerItemId': 9, 'price': '100', 'feePercent': '10'})

    def test_resources_and_individual_town_stone_have_distinct_payloads(self):
        for code in ('BOSS_ENTRY_TICKET', 'ATONEMENT_STONE', 'TREASURE_STONE'):
            self.assertEqual(listing_payload({'itemCode': code, 'quantity': 2}, 1, '100', '10'),
                             {'itemKind': code, 'quantity': 1, 'price': '100', 'feePercent': '10'})
        item = {'itemCode': 'TOWN_STONE', 'stoneId': 27}
        self.assertEqual(listing_payload(item, 1, '100', '10'),
                         {'itemKind': 'TOWN_STONE', 'stoneId': 27, 'quantity': 1, 'price': '100', 'feePercent': '10'})
        self.assertEqual(listing_key(item), ('stone', '27'))

    def test_potion_bundle_validates_inventory_and_step(self):
        item = {'itemCode': 'HEALTH_POTION', 'quantity': 35}
        self.assertEqual(listing_payload(item, 30, '100', '10')['quantity'], 30)
        for quantity in (1, 15, 40, 50, 60, None):
            with self.assertRaises(ValueError):
                listing_payload(item, quantity, '100', '10')

    def test_unknown_locked_missing_ids_and_stamina_are_rejected(self):
        for item in ({'itemCode': 'STAMINA_POTION', 'quantity': 50},
                     {'itemCode': 'UNKNOWN', 'slotType': 'OTHER', 'quantity': 50},
                     {'slotType': 'WEAPON'}, {'slotType': 'WEAPON', 'playerItemId': -3},
                     {'slotType': 'WEAPON', 'playerItemId': 1, 'isListed': True},
                     {'itemCode': 'TOWN_STONE', 'quantity': 1}):
            with self.assertRaises(ValueError):
                listing_payload(item, 1, '100', '10')
