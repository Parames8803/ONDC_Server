from speech_recognition import Recognizer, AudioFile, UnknownValueError, RequestError
from deep_translator import GoogleTranslator

def translate_audio(file_path, target_language='en'):
    r = Recognizer()

    with AudioFile(file_path) as source:
        try:
            audio_text = r.record(source)  # Record instead of listen for pre-recorded audio files
            text = r.recognize_google(audio_text)
            print('Converting audio transcripts into text ...')
            print('Original Text:', text)

            # Translate using deep-translator
            translation = GoogleTranslator(source='auto', target=target_language).translate(text)
            print('Translated Text:', translation)

            return translation

        except UnknownValueError:
            print('Speech Recognition could not understand the audio.')
            return "Could not understand the audio."
        except RequestError as e:
            print(f"Could not request results from Google Speech Recognition service; {e}")
            return f"API request error: {e}"
