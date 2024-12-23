const Configuration = {
    // See https://github.com/conventional-changelog/commitlint/blob/master/%40commitlint/config-conventional/src/index.ts
    extends: ['@commitlint/config-conventional'],
    rules: {
        'subject-case': [
            0,
            'never',
            // Allow Sentence-case. See https://commitlint.js.org/reference/rules.html#subject-case
            ['start-case', 'pascal-case', 'upper-case']
        ]
    }
};

module.exports = Configuration;