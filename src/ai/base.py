from abc import ABC,abstractmethod
from database import User
class AIModel(ABC):
    @abstractmethod
    def chat(self,prompt:str,user:User)->str:
        ''' sends a prompt to ai model and returns back the response'''
        pass
