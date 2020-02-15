from pydantic import BaseModel
from accountsvc import datatypes
from abc import ABC, abstractmethod
from typing import Optional

import aiomysql
import bcrypt


class PHPCASUserInfo(BaseModel):
    id: int
    enabled: bool = True
    admin: bool = False
    email: str
    name: str
    password: str
    real_name: str

    def check_password(self, plaintext: str) -> bool:
        return bcrypt.checkpw(plaintext.encode(), self.password.encode())


class PHPCASAdaptor(ABC):
    @classmethod
    async def create(cls, config) -> 'PHPCASAdaptor':
        pass

    def __init__(self, config: datatypes.Settings):
        pass

    async def get_user_by_email(self, email: str) -> Optional[PHPCASUserInfo]:
        pass

    async def get_user_by_username(self, username: str) -> Optional[PHPCASUserInfo]:
        pass


class FakePHPCASAdaptor(PHPCASAdaptor):
    @classmethod
    async def create(cls, config) -> 'FakePHPCASAdaptor':
        return FakePHPCASAdaptor(config=config)

    def __init__(self, config: datatypes.Settings):
        pass

    async def get_user_by_email(self, email: str) -> Optional[PHPCASUserInfo]:
        if email == 'testph@bitnp.net':
            # pw: testphp
            return PHPCASUserInfo(id=1, email=email, name="testph", password='$2b$12$JCc.2OHhGup1Jt12Bdyz5eXebeLfCk0Etix.G7HXRoJCWX8eGDE0K', real_name="TEST")
        elif email == 'test@phy25.com':
            # pw: test (pwpolicy violation)
            return PHPCASUserInfo(id=2, email=email, name="testphp", password="$2b$12$uQ7eceNo4mw6ljQYUjiUJ.KylZ.D5pld1lpO5giqrX8ltezhmWExG", real_name="TEST")
        elif email == 'test@bitnp.net':
            # pw: test (pwpolicy violation)
            return PHPCASUserInfo(id=20, email=email, name="test", password="$2b$12$uQ7eceNo4mw6ljQYUjiUJ.KylZ.D5pld1lpO5giqrX8ltezhmWExG", real_name="TEST")
        else:
            return None

    async def get_user_by_username(self, username: str) -> Optional[PHPCASUserInfo]:
        # pw: test (pwpolicy)
        if username == 'testphp':
            return PHPCASUserInfo(id=2, email="testphp@bitnp.net", name=username, password="$2b$12$uQ7eceNo4mw6ljQYUjiUJ.KylZ.D5pld1lpO5giqrX8ltezhmWExG", real_name="TEST")
        elif username == 'test':
            return PHPCASUserInfo(id=3, email="test@phy25.com", name=username, password="$2b$12$uQ7eceNo4mw6ljQYUjiUJ.KylZ.D5pld1lpO5giqrX8ltezhmWExG", real_name="TEST")
        else:
            return None


class MySQLPHPCASAdaptor(PHPCASAdaptor):
    config: datatypes.Settings
    pool: aiomysql.Pool

    @classmethod
    async def create(cls, config) -> 'MySQLPHPCASAdaptor':
        self = MySQLPHPCASAdaptor(config)
        self.pool = await self.create_pool()
        return self

    def __init__(self, config: datatypes.Settings):
        self.config = config

    async def create_pool(self):
        if not self.config.phpcas_db:
            return None
        return await aiomysql.create_pool(host=self.config.phpcas_host,
            user=self.config.phpcas_user,
            password=self.config.phpcas_password,
            db=self.config.phpcas_db,
            charset='utf8mb4',
            cursorclass=aiomysql.cursors.DictCursor,
            autocommit=True)

    async def get_user_by_email(self, email: str) -> Optional[PHPCASUserInfo]:
        async with self.pool.acquire() as connection:
            async with connection.cursor() as cursor:
                sql = "SELECT * FROM `users` WHERE `email`=%s"
                await cursor.execute(sql, (email,))
                result = await cursor.fetchone() # Read a single record
                if result:
                    return PHPCASUserInfo.parse_obj(result)
                else:
                    return None

    async def get_user_by_username(self, username: str) -> Optional[PHPCASUserInfo]:
        async with self.pool.acquire() as connection:
            async with connection.cursor() as cursor:
                sql = "SELECT * FROM `users` WHERE `name`=%s"
                await cursor.execute(sql, (username,))
                result = await cursor.fetchone() # Read a single record
                if result:
                    return PHPCASUserInfo.parse_obj(result)
                else:
                    return None
