/**
 * Tests for launchPackage(). The table is test/fixtures/launch-cases.json;
 * scripts/contract-test.mjs gives the same table to `launch_package` of the
 * installed Credenzo and compares.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { launchPackage, packageKey, vetSpec } from '../../src/launchPackage';

interface Case {
  command: unknown;
  args: unknown;
  expect: null | { ecosystem: 'npm' | 'pypi'; name: string; version: string | null };
}

const CASES = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, '../../../test/fixtures/launch-cases.json'),
    'utf8'
  )
) as Case[];

suite('launchPackage', () => {
  for (const c of CASES) {
    test(`${JSON.stringify(c.command)} ${JSON.stringify(c.args)}`, () => {
      assert.deepStrictEqual(launchPackage(c.command, c.args), c.expect);
    });
  }

  test('the table has cases', () => {
    assert.ok(CASES.length >= 40);
  });

  test('vetSpec and packageKey', () => {
    assert.strictEqual(vetSpec({ ecosystem: 'npm', name: '@a/b', version: '1.2.3' }), '@a/b@1.2.3');
    assert.strictEqual(vetSpec({ ecosystem: 'pypi', name: 'a-b', version: '1.2' }), 'a-b==1.2');
    assert.strictEqual(vetSpec({ ecosystem: 'pypi', name: 'a-b', version: null }), 'a-b');
    assert.strictEqual(packageKey({ ecosystem: 'npm', name: 'a', version: null }), 'npm:a');
    assert.notStrictEqual(
      packageKey({ ecosystem: 'npm', name: 'mcp', version: null }),
      packageKey({ ecosystem: 'pypi', name: 'mcp', version: null })
    );
  });

  test('a very long argument list or argument is declined', () => {
    assert.strictEqual(launchPackage('npx', new Array(65).fill('-y')), null);
    assert.strictEqual(launchPackage('npx', ['a'.repeat(513)]), null);
  });
});
