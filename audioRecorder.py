import pyaudio
import wave
import threading

class AudioRecorder:
    def __init__(self):
        self.audio = None
        self.frames = []
        self.is_recording = False
        self.stream = None

    def start_recording(self):
        if not self.is_recording:
            self.audio = pyaudio.PyAudio()  # Initialize PyAudio each time to reset
            self.stream = self.audio.open(format=pyaudio.paInt16,
                                          channels=1,
                                          rate=44100,
                                          input=True,
                                          input_device_index=1,
                                          frames_per_buffer=1024)
            self.is_recording = True
            self.frames = []

            def record():
                while self.is_recording:
                    data = self.stream.read(1024)
                    self.frames.append(data)

            self.record_thread = threading.Thread(target=record)
            self.record_thread.start()

    def stop_recording(self):
        if self.is_recording:
            self.is_recording = False
            self.record_thread.join()
            self.stream.stop_stream()
            self.stream.close()
            self.audio.terminate()  # Properly terminate PyAudio

            sound_file = wave.open("record.wav", "wb")
            sound_file.setnchannels(1)
            sound_file.setsampwidth(self.audio.get_sample_size(pyaudio.paInt16))
            sound_file.setframerate(44100)
            sound_file.writeframes(b"".join(self.frames))
            sound_file.close()

            # Reset `self.audio` to None so it can be reinitialized on the next recording
            self.audio = None
