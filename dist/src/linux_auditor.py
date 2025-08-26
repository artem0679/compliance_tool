import paramiko
import logging

# Настраиваем логирование, чтобы видеть что происходит
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LinuxAuditor:
    def __init__(self, hostname, username, password=None, key_filename=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.client = None

    def connect(self):
        """Установка SSH соединения"""
        try:
            self.client = paramiko.SSHClient()
            # Автоматически добавляем хост в известные (осторожно в production!)
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.client.connect(
                hostname=self.hostname,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                timeout=10
            )
            logger.info(f"Successfully connected to {self.hostname}")
            return True
        except Exception as e:
            logger.error(f"Connection failed to {self.hostname}: {str(e)}")
            return False

    def execute_command(self, command):
        """Выполнение команды на удаленной машине"""
        if not self.client:
            raise Exception("Not connected to host")
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            if error:
                logger.warning(f"Command '{command}' returned error: {error}")
            
            return output, error
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            return "", str(e)

    def disconnect(self):
        """Закрытие соединения"""
        if self.client:
            self.client.close()
            logger.info(f"Disconnected from {self.hostname}")

    def get_ssh_config(self):
        """Получение конфигурации SSH"""
        output, error = self.execute_command("cat /etc/ssh/sshd_config")
        return output

    def check_ssh_protocol(self):
        """Проверка версии протокола SSH"""
        config = self.get_ssh_config()
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('Protocol') and not line.startswith('#'):
                protocol_version = line.split()[1]
                return protocol_version == '2'
        return False