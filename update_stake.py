# coding: utf8

import requests
import json
import os
import time
import pymysql.cursors


connection = pymysql.connect(host='127.0.0.1', port=3306, user='ub', password='UB@018_world_cup', db='db_world_cup',
                             charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
g_stake_address = [
    '18QQJNannotKo2Q9CkiqBJcf4qZWANZvGM',
    '16JUBxCKb5LsQP7pZANc2yWpqvv4Xxqpw5',
    '17ThubQK723mnUAhJyQ5g3y7WGExMu5X1d',
    # '1BdR8SFVB67JbLdbtJBagN4oFGvUGYqUjh',
    '1EvSWArvHhg2LxDBBSqDmyabqKpJXh2dVW',
    '1Kn4scG7XnyHkWS8JXBEnHv1rHZuatKK1r',
    '141fdMZPSXyx1Ym73Tf7f5PgLrw4sTaRcG',
    '13QXEiy8nfSiZa5co2bMCcKXbbDTCUaqPd',
    '1EiiEpwmueb5gnPaf83QMfpZZa6NHa5xyu',
    '1Q82uttbmSsiTSb3xkk16u5bY3Vd8NJi1k',
    '1NCbHsPT7ET1W5M1eUxfdRnecUHKWifLey',
    '12fZL8ujSoDyf1JGG5bwTZveMfpBnKNbjK',
    '1DvETyyKTNbTVi8YFeqJcQGMz6PAbsgSc2',
    '1N91rYn2vcuZH9twrx9sZEbMD1Va4oxb8M',
    '16K7C5qHL7mRY31Wu4dGXx6DgHrHvrPMEm',
    '16VCNicr93VhLQuFgJaXu8JmbJubA68fnS',
    '17gEQUDzoBucaDb5yNVf7h9RwzR8h8ndWc',
    '19JrzBCwat2yEy2Y7LZpkKozgffCNoc5mz',
    '1Axnf6NNABo8VnDyFYk7FEajuNtSFjRYZw',
    '13BauCmfa5JNoHxtQaeWoWT1Xqwree6HZx',
    '1BYunn44TecdU1tRWtSnxpPhYbAA99rGm1',
    '18L1zzKrNwL2Huov1iUdCuUr1HE1e7tFLk',
    '18hsZYuXmD2oBHdxnWLTqVAaX9Ge7t8KxB',
    '1FNNeq9Wpq1TQ2C1iLYQL3zn3BHAkh12dp',
    '15hoi9mLw53ATgMdtwdMgtJUUin6cTwxYc',
    '19Eb7zndhKVVozm4AD9e3KtxbESBvZZqLa',
    '1KdK3LMNjrPaRhn7i3evGX5uxBhhP2nTsw',
    '1HpTt76LdQG21QFttRtNGPqTcF6Tjbh2hY',
    '1NK6KkGo1uYCq1Xv4GZ9gL3217UbqbFygP',
    '15amvgyWfrCyFtr1r1NXX3GLoAzUX6pE2w',
    '1BaTnykKitJ5mG8RJXfR1YNbcnDF8ZDHcF',
    '12LGWm2ovNiKVafAm9GbEmDbQdz7ezGeto',
    '1FbQBr2fg9aQyJp1HhsENFGo6tdcNjpguc'
]

class StateManager(object):
    def __init__(self):
        self.id_file = 'id_file'
        try:
            f = os.open(self.id_file, os.O_RDONLY)
            self.latest_id = os.read(f, 10)
            os.close(f)
            if self.latest_id is None:
                self.latest_id = '1'
            else:
                self.latest_id = self.latest_id.decode('ascii')
        except:
            self.latest_id = '1'

    def get_last_id(self):
        return self.latest_id

    def increase_last_id(self, id):
        if id > self.latest_id:
            self.latest_id = id

    def save_latest_id(self):
        try:
            os.remove(self.id_file)
        except:
            pass
        f = os.open(self.id_file, os.O_WRONLY | os.O_TRUNC | os.O_CREAT)
        os.write(f, self.latest_id.encode('ascii'))
        os.close(f)
        print(self.latest_id)

    def __del__(self):
        self.save_latest_id()


def update_database(address, count, time, item, isAnybit):
    cursor = connection.cursor()
    sql = "INSERT INTO `t_stake` (`address`, `count`, `time`, `type`, `item`, `txid`, `isAnybit`) VALUES ('%s', %d, '%s', 2, %d, '', %d) ON DUPLICATE KEY UPDATE count=VALUES(count)" % \
          (address, count, time, item, isAnybit)
    cursor.execute(sql)
    connection.commit()


def get_latest_transaction(last_id, address, item):
    query_trans_request = '''{
    "header": {
            "version": "1.0.1", 
            "language": "zh", 
            "trancode": "tran_page", 
            "clienttype": "Android", 
            "walletid": "927fc097c3567fe119cde85529fb7630fc1b690a", 
            "random": "123456",
            "handshake": "abcdefg", 
            "imie": "abcdefg"
        }, 
        "body": {
                     "coinAddr":"%s",
                     "coinType":"UBTC",
                     "queryType":"1",
                     "lastId":%d,
                     "limit":10
          }
    }
    ''' % (address, int(last_id))
    query_headers = {'Content-Type': "application/json"}
    # print(query_trans_request)
    response = requests.post('https://www.anybit.io/server/process/', data=query_trans_request, headers=query_headers)
    # response = requests.post('http://192.168.1.220:8080/lightwallet/server/process', data=query_trans_request, headers=query_headers)
    # print(response.text)

    records = json.loads(response.text)['data']['trans']
    latest_id = int(last_id)
    for r in records:
        print(r['targetAddr'] + ': ' + str(r['tranAmt']))
        if latest_id < r['id']:
            latest_id = r['id']
        if 'source' in r and r['source'] == 1:
            count = int(float(r['tranAmt']) * 10 * 5 / 4)
            isAnybit = 1
        else:
            count = int(float(r['tranAmt']) * 10)
            isAnybit = 0
        if count <= 0:
            continue
        ctime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r['createTime'] / 1000))
        # item = g_stake_address.index(r['targetAddr'])
        print(r['targetAddr'], count, ctime, item)
        update_database(r['targetAddr'], count, ctime, item, isAnybit)
    return latest_id


if __name__ == '__main__':
    sm = StateManager()
    while True:
        item = 1
        for a in g_stake_address:
            last_id = get_latest_transaction(sm.get_last_id(), a, item)
            item += 1
            sm.increase_last_id(str(last_id))
        sm.save_latest_id()
        time.sleep(30)
    # print('end: ', sm.get_last_id())