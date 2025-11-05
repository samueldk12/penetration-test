#!/usr/bin/env python3
"""
Script para executar todos os testes automatizados
"""

import unittest
import sys
import os

# Adiciona o diretório pai ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_all_tests():
    """Executa todos os testes"""
    # Descobre todos os testes no diretório tests
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(os.path.abspath(__file__))
    suite = loader.discover(start_dir, pattern='test_*.py')

    # Executa os testes
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Retorna código de saída baseado no resultado
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    print("="*80)
    print("EXECUTANDO TESTES AUTOMATIZADOS - PENTEST SUITE")
    print("="*80)
    print()

    exit_code = run_all_tests()

    print()
    print("="*80)
    if exit_code == 0:
        print("✓ TODOS OS TESTES PASSARAM!")
    else:
        print("✗ ALGUNS TESTES FALHARAM")
    print("="*80)

    sys.exit(exit_code)
