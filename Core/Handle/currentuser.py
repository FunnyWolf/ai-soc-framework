# -*- coding: utf-8 -*-
# @File  : currentuser.py
# @Date  : 2021/2/25
# @Desc  :
class CurrentUser(object):
    def __init__(self):
        pass

    @staticmethod
    def list(user=None):
        current_info = {
            'name': user.username,
            'currentAuthority': 'admin',
            'userid': user.id,
        }

        return current_info
