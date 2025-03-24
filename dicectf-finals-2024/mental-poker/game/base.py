from abc import ABC, abstractmethod


class Game(ABC):

	@classmethod
	@abstractmethod
	def check(cls, transcript: list[str]) -> tuple[bool, str]:
		'''
		Determines the winner of a complete transcript.
		Returns False if guesser wins or True if setter
		wins, along with a reason.
		'''
		pass

class Alice(ABC):

    @abstractmethod
    def first_message(self) -> str:
        '''
        Computes the guesser's first message.
        '''
        pass

    @abstractmethod
    def second_message(self, transcript: tuple[str, str]) -> str:
        '''
        Computes the guesser's second message based on its
        current state and a partial transcript.
        '''
        pass

    def cheated(self, transcript: tuple[str, str, str, str]):
        '''
        Checks if the setter cheated based on the full transcript.
        '''
        del transcript
        return False

class Bob(ABC):

    @abstractmethod
    def first_response(self, transcript: tuple[str]) -> str:
        '''
        Computes the setter's first response based on the partial transcript.
        '''
        pass

    @abstractmethod
    def second_response(self, transcript: tuple[str, str, str]) -> str:
        '''
        Computes the setter's second response based on the partial transcript.
        '''
        pass
