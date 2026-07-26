#!/usr/bin/env node
// Renders prisma/schema.template.prisma into one concrete schema per supported
// database. Prisma cannot read `datasource provider` from an environment
// variable, so supporting both PostgreSQL and SQLite means committing one
// generated schema each. Generating them from a single template is what keeps
// the two from drifting.
//
//   npm run db:schema        write the generated schemas
//   npm run db:schema:check        verify the committed output matches the template

const fs = require("node:fs");
const path = require("node:path");

const PROVIDERS = ["postgresql", "sqlite"];
const ROOT = path.resolve(__dirname, "..");
const TEMPLATE = path.join(ROOT, "prisma", "schema.template.prisma");

const HEADER = (provider) => `// GENERATED FILE — DO NOT EDIT.
// Source: prisma/schema.template.prisma
// Provider: ${provider}
// Regenerate with: npm run db:schema
`;

function render(template, provider) {
  if (!template.includes("__PROVIDER__")) {
    throw new Error("prisma/schema.template.prisma must contain a __PROVIDER__ placeholder");
  }
  return `${HEADER(provider)}${template.replaceAll("__PROVIDER__", provider)}`;
}

function targetFor(provider) {
  return path.join(ROOT, "prisma", provider, "schema.prisma");
}

function main() {
  const check = process.argv.includes("--check");
  const template = fs.readFileSync(TEMPLATE, "utf8");
  let failed = false;

  for (const provider of PROVIDERS) {
    const target = targetFor(provider);
    const rendered = render(template, provider);
    if (check) {
      const existing = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : "";
      if (existing !== rendered) {
        process.stderr.write(`schema out of date: prisma/${provider}/schema.prisma\n`);
        failed = true;
      }
      continue;
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, rendered);
    process.stdout.write(`wrote prisma/${provider}/schema.prisma\n`);
  }

  if (failed) {
    process.stderr.write("Run `npm run db:schema` and commit the result.\n");
    process.exitCode = 1;
    return;
  }
  if (check) process.stdout.write("generated schemas are up to date\n");
}

main();
