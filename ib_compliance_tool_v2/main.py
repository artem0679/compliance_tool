import os
import yaml
import json
import html
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

def print_summary_statistics(all_results):
    """Вывод сводной статистики"""
    console.print(f"\n[bold yellow]📊 СВОДНАЯ СТАТИСТИКА[/bold yellow]")
    console.print("=" * 50)
    
    total_hosts = len(all_results)
    completed = sum(1 for r in all_results if r['status'] == 'completed')
    failed = sum(1 for r in all_results if r['status'] == 'failed')
    errors = sum(1 for r in all_results if r['status'] == 'error')
    
    console.print(f"Всего машин: {total_hosts}")
    console.print(f"Успешно проверено: [green]{completed}[/green]")
    console.print(f"Неудачных проверок: [yellow]{failed}[/yellow]")
    console.print(f"Ошибок подключения: [red]{errors}[/red]")
    
    # Статистика по проверкам для успешных хостов
    if completed > 0:
        total_checks = sum(len(r['results']) for r in all_results if r['status'] == 'completed')
        total_passed = sum(r['summary']['passed'] for r in all_results if r['status'] == 'completed')
        total_failed = sum(r['summary']['failed'] for r in all_results if r['status'] == 'completed')
        
        console.print(f"\n[bold]По всем успешным проверкам:[/bold]")
        console.print(f"Всего проверок: {total_checks}")
        console.print(f"Успешных: [green]{total_passed}[/green]")
        console.print(f"Неуспешных: [red]{total_failed}[/red]")
        success_rate = (total_passed / total_checks * 100) if total_checks > 0 else 0
        console.print(f"Процент успеха: [bold]{success_rate:.1f}%[/bold]")

def save_summary_report(all_results):
    """Сохранение сводного отчета по всем машинам"""
    summary = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_hosts': len(all_results),
            'completed': sum(1 for r in all_results if r['status'] == 'completed'),
            'failed': sum(1 for r in all_results if r['status'] == 'failed'),
            'errors': sum(1 for r in all_results if r['status'] == 'error')
        },
        'hosts': all_results
    }
    
    # Создаем папку reports если ее нет
    os.makedirs('reports', exist_ok=True)
    
    json_filename = f"reports/summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    html_filename = save_html_report(all_results)
    
    console.print(f"[green]✓ JSON отчет сохранен: {json_filename}[/green]")
    console.print(f"[green]✓ HTML отчет сохранен: {html_filename}[/green]")

def print_banner():

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
        width=65,

    )
    aligned_panel = Align(panel, align="center", pad=10)
    console.print()
    console.print(aligned_panel)
    console.print()

def save_html_report(all_results):
    """Сохранение отчета в HTML формате с collapsing sections"""
    import os
    os.makedirs('reports', exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    # Подсчет статистики
    total_hosts = len(all_results)
    completed = sum(1 for r in all_results if r['status'] == 'completed')
    failed = sum(1 for r in all_results if r['status'] == 'failed')
    errors = sum(1 for r in all_results if r['status'] == 'error')
    
    html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report - GOZNAK</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 3px solid #2c5aa0;
            padding-bottom: 20px;
        }}
        .logo {{
            font-size: 32px;
            font-weight: bold;
            color: #2c5aa0;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            font-style: italic;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 4px solid #2c5aa0;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }}
        .stat-item {{
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            min-width: 120px;
        }}
        .stat-completed {{ background: #d4edda; color: #155724; }}
        .stat-failed {{ background: #f8d7da; color: #721c24; }}
        .stat-errors {{ background: #fff3cd; color: #856404; }}
        
        /* Стили для сворачиваемых секций */
        .collapsible {{
            background: #2c5aa0;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            cursor: pointer;
            font-weight: bold;
        }}
        .collapsible:hover {{
            background: #1e3a8a;
        }}
        .collapsible-content {{
            display: none;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }}
        .collapsible:after {{
            content: '▼';
            float: right;
        }}
        .active:after {{
            content: '▲';
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }}
        th {{
            background-color: #2c5aa0;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .status-pass {{ color: green; font-weight: bold; }}
        .status-fail {{ color: red; font-weight: bold; }}
        .status-error {{ color: orange; font-weight: bold; }}
        .timestamp {{
            text-align: right;
            color: #666;
            font-size: 12px;
            margin-top: 30px;
        }}
        .error-box {{
            color: red; 
            padding: 10px; 
            background: #ffe6e6; 
            border-radius: 5px;
            margin: 10px 0;
        }}
        .warning-box {{
            color: orange; 
            padding: 10px; 
            background: #fff3cd; 
            border-radius: 5px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">GOZNAK</div>
            <div class="subtitle">Compliance Check Tool</div>
            <h1>Отчет проверки соответствия</h1>
        </div>

        <div class="summary">
            <h2>Сводная статистика</h2>
            <div class="stats">
                <div class="stat-item stat-completed">
                    <div style="font-size: 24px; font-weight: bold;">{completed}</div>
                    <div>Успешно</div>
                </div>
                <div class="stat-item stat-failed">
                    <div style="font-size: 24px; font-weight: bold;">{failed}</div>
                    <div>Неудачно</div>
                </div>
                <div class="stat-item stat-errors">
                    <div style="font-size: 24px; font-weight: bold;">{errors}</div>
                    <div>Ошибки</div>
                </div>
            </div>
            <p><strong>Всего машин:</strong> {total_hosts}</p>
            <p><strong>Время проверки:</strong> {timestamp}</p>
        </div>
"""

    # Добавляем результаты по каждой машине
    for i, host_result in enumerate(all_results):
        host = host_result['host']
        status = host_result['status']
        results = host_result.get('results', [])
        
        status_text = "✅ УСПЕШНО" if status == 'completed' else "⚠️  НЕУДАЧНО" if status == 'failed' else "❌ ОШИБКА"
        
        html_content += f"""
        <button type="button" class="collapsible" onclick="toggleSection('host-{i}')">
            {status_text} | Машина: {host}
        </button>
        <div id="host-{i}" class="collapsible-content">
"""
        
        if status == 'completed' and results:
            passed = sum(1 for r in results if r['status'] == 'PASS')
            failed = sum(1 for r in results if r['status'] == 'FAIL')
            html_content += f"""
            <div style="margin-bottom: 15px;">
                <strong>Результаты:</strong> PASS: <span style="color: green">{passed}</span>, 
                FAIL: <span style="color: red">{failed}</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Правило</th>
                        <th>Название</th>
                        <th>Статус</th>
                        <th>Ожидаемое</th>
                        <th>Фактическое</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for result in results:
                status_class = ""
                if result['status'] == 'PASS':
                    status_class = "status-pass"
                elif result['status'] == 'FAIL':
                    status_class = "status-fail"
                else:
                    status_class = "status-error"
                
                html_content += f"""
                    <tr>
                        <td>{result['id']}</td>
                        <td>{html.escape(str(result['name']))}</td>
                        <td class="{status_class}">{result['status']}</td>
                        <td>{html.escape(str(result.get('expected', 'N/A')))}</td>
                        <td>{html.escape(str(result.get('actual_display', result.get('actual', 'N/A'))))}</td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
            """
        elif status == 'error':
            html_content += f"""
            <div class="error-box">
                <strong>Ошибка подключения:</strong> {html.escape(host_result.get('error', 'Unknown error'))}
            </div>
            """
        else:
            html_content += """
            <div class="warning-box">
                <strong>Нет результатов проверки</strong>
            </div>
            """
        
        html_content += """
        </div>
        """

    html_content += f"""
        <div class="timestamp">
            Отчет сгенерирован: {timestamp}
        </div>

        <script>
            function toggleSection(id) {{
                var content = document.getElementById(id);
                var button = content.previousElementSibling;
                if (content.style.display === "block") {{
                    content.style.display = "none";
                    button.classList.remove("active");
                }} else {{
                    content.style.display = "block";
                    button.classList.add("active");
                }}
            }}
            
            // Автоматически открыть первую секцию
            document.addEventListener('DOMContentLoaded', function() {{
                var firstSection = document.querySelector('.collapsible-content');
                if (firstSection) {{
                    firstSection.style.display = 'block';
                    firstSection.previousElementSibling.classList.add('active');
                }}
            }});
        </script>
    </div>
</body>
</html>
"""

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename

def main():
    """Основная функция с улучшенным интерфейсом"""
    try:
        print_banner()
        
        # Запрос списка хостов
        console.print("[bold cyan]ВВОД СПИСКА МАШИН[/bold cyan]")
        console.print("[italic]Укажите IP-адреса или hostname через запятую[/italic]")
        console.print("[italic]Пример: 192.168.1.10, 192.168.1.11, server01.domain.com[/italic]")
        
        hosts_input = console.input("\n➤ [cyan]Машины: [/cyan]").strip()
        hosts = [host.strip() for host in hosts_input.split(',') if host.strip()]
        
        if not hosts:
            console.print("[red]❌ Не указано ни одной машины![/red]")
            return
        
        # Запрос учетных данных
        console.print(f"\n[cyan]📊 Будет проверено машин: {len(hosts)}[/cyan]")
        username = console.input("➤ [cyan]👤 Имя пользователя: [/cyan]").strip()
        if not username:
            console.print("[red]❌ Имя пользователя не может быть пустым![/red]")
            return
            
        password = getpass.getpass("➤ 🔒 Пароль: ")
        if not password:
            console.print("[red]❌ Пароль не может быть пустым![/red]")
            return
        
        rules_file = "compliance_rules/linux.yaml"
        
        # Обработка всех хостов
        all_results = []
        console.print(f"\n[bold yellow]🚀 НАЧИНАЕМ ПРОВЕРКУ...[/bold yellow]")
        
        for i, host in enumerate(hosts, 1):
            console.print(f"\n[bold green]🔍 [{i}/{len(hosts)}] Проверка {host}[/bold green]")
            console.print("[italic]Подключаемся...[/italic]")
            
            try:
                results = run_linux_audit(host, username, password, rules_file)
                
                if results:
                    passed = sum(1 for r in results if r['status'] == 'PASS')
                    failed = sum(1 for r in results if r['status'] == 'FAIL')
                    errors = sum(1 for r in results if r['status'] == 'ERROR')
                    
                    all_results.append({
                        "host": host, 
                        "results": results, 
                        "status": "completed",
                        "summary": {"passed": passed, "failed": failed, "errors": errors}
                    })
                    
                    console.print(f"[green]✅ Успешно! PASS: {passed}, FAIL: {failed}, ERROR: {errors}[/green]")
                    print_results_table(host, results)
                else:
                    all_results.append({
                        "host": host, 
                        "results": [], 
                        "status": "failed", 
                        "error": "No results from audit"
                    })
                    console.print("[yellow]⚠️  Проверка не дала результатов[/yellow]")
                    
            except Exception as e:
                error_msg = f"Ошибка: {str(e)}"
                all_results.append({
                    "host": host, 
                    "results": [], 
                    "status": "error", 
                    "error": error_msg
                })
                console.print(f"[red]❌ {error_msg}[/red]")
        
        # Сводная статистика
        print_summary_statistics(all_results)
        
        # Сохранение отчета
        save_summary_report(all_results)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Проверка прервана пользователем[/yellow]")
    except Exception as e:
        console.print(f"[red]💥 Критическая ошибка: {e}[/red]")
        import traceback
        traceback.print_exc()
    finally:
        input("\n⏎ Нажмите Enter для выхода...")

    
if __name__ == "__main__":
    main()