module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom', // Changed to jsdom for integration tests
  testMatch: [
    '**/__TESTS/**/*.test.ts',
    '**/__TESTS/**/*.test.js'
  ],
  setupFilesAfterEnv: ['<rootDir>/__TESTS/setup.js'], // Test setup file
  collectCoverageFrom: [
    'static/js/**/*.{js,ts}',
    '!static/js/**/*.d.ts',
    '!static/js/**/*.test.{js,ts}'
  ],
  coverageDirectory: '__TESTS/coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  testTimeout: 30000, // 30 seconds for integration tests
  maxWorkers: 4, // Limit concurrent test workers
  verbose: true,
  globals: {
    'ts-jest': {
      useESM: true
    }
  },
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/static/js/$1'
    // Note: @modules mapping removed in Task 8 due to broken module system
  }
};