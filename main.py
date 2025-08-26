import yaml
import json
import getpass
from datetime import datetime
from src.linux_auditor import LinuxAuditor
from rich.console import Console
from rich.table import Table
from rich.align import Align
from rich.box import ROUNDED
from rich.panel import Panel

console = Console()

def load_rules(rules_file):
    """Загрузка правил из YAML файла"""
    with open(rules_file, 'r') as f:
        return yaml.safe_load(f)

def get_password():
    """Безопасный ввод пароля"""
    return getpass.getpass("Введите пароль: ")

def run_linux_audit(host, username, password, rules_file):
    """Запуск аудита для Linux хоста"""
    
    # Загружаем правила
    rules_data = load_rules(rules_file)
    rules = rules_data.get('rules', [])
    
    # Создаем аудитор и подключаемся
    auditor = LinuxAuditor(host, username, password)
    if not auditor.connect():
        return None
    
    results = []
    
    # Выполняем проверки по каждому правилу
    for rule in rules:
        rule_id = rule['id']
        rule_name = rule['name']
        rule_type = rule.get('type', 'text')
        
        try:
            # Выполняем команду из правила
            output, error = auditor.execute_command(rule['check']['command'])
            
            # Умная проверка в зависимости от типа
            expected = rule['check']['expect']
            status = "FAIL"
            actual_display = output
            
            if rule_type == 'numeric_max':
                # Числовая проверка на "не более" (<=)
                actual_value = extract_number(output)
                expected_value = extract_number(expected)
                
                if actual_value is not None and expected_value is not None:
                    status = "PASS" if actual_value <= expected_value else "FAIL"
                    actual_display = f"{actual_value} (<= {expected_value})"
                else:
                    status = "ERROR"
                    actual_display = f"Failed to extract numbers: {output}"
                    
            elif rule_type == 'numeric_min':
                # Числовая проверка на "не менее" (>=)
                actual_value = extract_number(output)
                expected_value = extract_number(expected)
                
                if actual_value is not None and expected_value is not None:
                    status = "PASS" if actual_value >= expected_value else "FAIL"
                    actual_display = f"{actual_value} (>= {expected_value})"
                else:
                    status = "ERROR"
                    actual_display = f"Failed to extract numbers: {output}"
                    
            elif rule_type == 'numeric_equals':
                # Точное числовое совпадение (==)
                actual_value = extract_number(output)
                expected_value = extract_number(expected)
                
                if actual_value is not None and expected_value is not None:
                    status = "PASS" if actual_value == expected_value else "FAIL"
                    actual_display = f"{actual_value} (== {expected_value})"
                else:
                    status = "ERROR"
                    actual_display = f"Failed to extract numbers: {output}"
                    
            elif rule_type == 'contains':
                # Проверка на наличие подстроки
                status = "PASS" if expected in output else "FAIL"
                actual_display = output
                
            elif rule_type == 'not_contains':
                # Проверка на отсутствие подстроки
                status = "PASS" if expected not in output else "FAIL"
                actual_display = output
                
            elif rule_type == 'text':
                # Точное текстовое совпадение
                status = "PASS" if output.strip() == expected.strip() else "FAIL"
                actual_display = output
                
            elif rule_type == 'contains_multiple':
                # Проверка на наличие нескольких подстрок
                all_found = all(substring in output for substring in expected.split())
                status = "PASS" if all_found else "FAIL"
                actual_display = output
                
            elif rule_type == 'file_contains_lines':
                # Проверка что файл содержит все указанные строки
                expected_lines = expected.strip().split('\n')
                missing_lines = []
                for line in expected_lines:
                    if line.strip() and line.strip() not in output:
                        missing_lines.append(line.strip())
                
                status = "PASS" if not missing_lines else "FAIL"
                actual_display = f"Missing lines: {missing_lines}" if missing_lines else "All lines found"
                
            else:
                # Старая текстовая проверка (для совместимости)
                status = "PASS" if expected in output else "FAIL"
                actual_display = output
            
            result = {
                'id': rule_id,
                'name': rule_name,
                'type': rule_type,
                'status': status,
                'expected': expected,
                'actual': output,
                'actual_display': actual_display,
                'error': error
            }
            
            results.append(result)
            
        except Exception as e:
            result = {
                'id': rule_id,
                'name': rule_name,
                'status': 'ERROR',
                'error': str(e)
            }
            results.append(result)
    
    auditor.disconnect()
    return results

def extract_number(text):
    """Извлекает первое число из текста"""
    import re
    numbers = re.findall(r'\d+', str(text))
    return int(numbers[0]) if numbers else None

def print_results_table(host, results):
    """Красивый вывод результатов в таблице"""
    table = Table(title=f"Compliance Check Results for {host}")
    
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("Status", style="bold")
    table.add_column("Expected")
    table.add_column("Actual")
    
    for result in results:
        status_style = "green" if result['status'] == 'PASS' else "red"
        actual = result.get('actual_display', result.get('actual', 'N/A'))
        actual = (actual[:47] + "...") if len(str(actual)) > 50 else actual
        
        table.add_row(
            result['id'],
            result['name'],
            f"[{status_style}]{result['status']}[/{status_style}]",
            result.get('expected', 'N/A'),
            str(actual)
        )
    
    console.print(table)

def save_json_report(results, host):
    """Сохранение отчета в JSON файл"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'host': host,
        'results': results
    }
    
    # Создаем папку reports если ее нет
    import os
    os.makedirs('reports', exist_ok=True)
    
    filename = f"reports/report_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    console.print(f"[green]Report saved to {filename}[/green]")

def main():

    banner_text = """
     ██████╗  ██████╗ ███████╗███╗   ██╗ █████╗ ██╗  ██╗
    ██╔════╝ ██╔═══██╗╚══███╔╝████╗  ██║██╔══██╗██║ ██╔╝
    ██║  ███╗██║   ██║  ███╔╝ ██╔██╗ ██║███████║█████╔╝ 
    ██║   ██║██║   ██║ ███╔╝  ██║╚██╗██║██╔══██║██╔═██╗ 
    ╚██████╔╝╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██╗
     ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝
    """
    
    panel = Panel(
        banner_text,
        title="[bold yellow]COMPLIANCE CHECK TOOL[/bold yellow]",
        subtitle="[italic]АО 'Гознак'[/italic]",
        box=ROUNDED,
        border_style="blue",
        width=65
    )
    console.print(panel)
    
    # Интерактивный ввод данных
    host = console.input("[cyan]Введите IP адрес хоста: [/cyan]").strip()
    username = console.input("[cyan]Введите имя пользователя: [/cyan]").strip()
    password = getpass.getpass("Введите пароль: ")
    rules_file = "compliance_rules/linux.yaml"
    
    console.print(f"\nStarting audit for host: [cyan]{host}[/cyan]")
    
    # Запускаем проверку
    results = run_linux_audit(host, username, password, rules_file)
    
    if results:
        # Выводим результаты
        print_results_table(host, results)
        
        # Сохраняем отчет
        save_json_report(results, host)
    else:
        console.print("[red]Audit failed - no results[/red]")
    
    input("\nНажмите Enter для выхода...")
    
if __name__ == "__main__":
    main()
