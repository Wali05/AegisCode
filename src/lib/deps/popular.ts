/**
 * Widely used package names, used as targets for lookalike (typosquat)
 * detection and to skip registry lookups for packages everyone already uses.
 * Not exhaustive — a name missing here is simply checked against the registry.
 */

export const POPULAR_NPM = [
  "react", "react-dom", "react-router", "react-router-dom", "next", "vue", "nuxt", "svelte", "angular", "@angular/core",
  "express", "koa", "fastify", "hono", "hapi", "nestjs", "@nestjs/core", "socket.io", "ws", "cors", "helmet", "morgan",
  "body-parser", "cookie-parser", "express-session", "passport", "jsonwebtoken", "bcrypt", "bcryptjs", "argon2",
  "lodash", "lodash-es", "underscore", "ramda", "immer", "zod", "yup", "joi", "ajv", "validator", "class-validator",
  "axios", "node-fetch", "got", "ky", "superagent", "undici", "cross-fetch", "isomorphic-fetch",
  "chalk", "commander", "yargs", "inquirer", "ora", "debug", "dotenv", "cross-env", "minimist", "glob", "rimraf",
  "fs-extra", "mkdirp", "chokidar", "semver", "uuid", "nanoid", "date-fns", "dayjs", "moment", "luxon",
  "mongoose", "mongodb", "pg", "mysql", "mysql2", "sqlite3", "better-sqlite3", "redis", "ioredis", "prisma",
  "@prisma/client", "sequelize", "typeorm", "knex", "drizzle-orm", "kysely",
  "typescript", "ts-node", "tsx", "esbuild", "vite", "webpack", "rollup", "parcel", "babel-loader", "@babel/core",
  "eslint", "prettier", "jest", "vitest", "mocha", "chai", "sinon", "supertest", "playwright", "puppeteer", "cypress",
  "tailwindcss", "postcss", "autoprefixer", "sass", "styled-components", "@emotion/react", "classnames", "clsx",
  "redux", "@reduxjs/toolkit", "react-redux", "zustand", "jotai", "mobx", "@tanstack/react-query", "swr",
  "graphql", "apollo-server", "@apollo/client", "graphql-request", "openai", "@anthropic-ai/sdk", "@google/genai",
  "langchain", "ai", "stripe", "twilio", "nodemailer", "aws-sdk", "@aws-sdk/client-s3", "firebase", "firebase-admin",
  "@supabase/supabase-js", "sharp", "jimp", "multer", "formidable", "busboy", "cheerio", "jsdom", "marked",
  "markdown-it", "highlight.js", "prismjs", "dompurify", "sanitize-html", "xss", "he", "qs", "query-string",
  "path-to-regexp", "rxjs", "async", "bluebird", "p-limit", "p-queue", "eventemitter3", "colors", "kleur",
  "winston", "pino", "bunyan", "js-yaml", "yaml", "xml2js", "fast-xml-parser", "csv-parse", "papaparse",
  "jszip", "archiver", "tar", "node-cron", "bull", "bullmq", "agenda", "pm2", "nodemon", "concurrently",
  "three", "d3", "chart.js", "recharts", "framer-motion", "motion", "lucide-react", "@radix-ui/react-dialog",
  "react-hook-form", "formik", "i18next", "react-i18next", "electron", "react-native", "expo",
] as const;

export const POPULAR_PYPI = [
  "requests", "urllib3", "httpx", "aiohttp", "flask", "django", "fastapi", "starlette", "uvicorn", "gunicorn",
  "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn", "torch", "tensorflow", "keras", "jax",
  "transformers", "datasets", "tokenizers", "openai", "anthropic", "langchain", "llama-index", "tiktoken",
  "pydantic", "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "psycopg", "pymysql", "pymongo", "redis",
  "celery", "boto3", "botocore", "google-cloud-storage", "azure-storage-blob", "pyyaml", "toml", "tomli",
  "python-dotenv", "click", "typer", "rich", "tqdm", "colorama", "pytest", "pytest-cov", "mock", "tox", "black",
  "ruff", "flake8", "pylint", "mypy", "isort", "setuptools", "wheel", "pip", "six", "attrs", "dataclasses-json",
  "jinja2", "markupsafe", "werkzeug", "itsdangerous", "cryptography", "pyjwt", "bcrypt", "passlib", "paramiko",
  "beautifulsoup4", "lxml", "html5lib", "selenium", "playwright", "scrapy", "pillow", "opencv-python",
  "python-dateutil", "pytz", "arrow", "pendulum", "orjson", "ujson", "simplejson", "msgpack", "protobuf",
  "grpcio", "websockets", "pyzmq", "docker", "kubernetes", "ansible", "fabric", "invoke", "networkx", "sympy",
  "statsmodels", "xgboost", "lightgbm", "catboost", "nltk", "spacy", "gensim", "streamlit", "gradio", "dash",
  "plotly", "bokeh", "jupyter", "notebook", "ipython", "pyarrow", "polars", "duckdb", "sentry-sdk", "loguru",
] as const;

/** Python import names that differ from their PyPI distribution names. */
export const PY_IMPORT_TO_DIST: Record<string, string> = {
  yaml: "pyyaml",
  cv2: "opencv-python",
  PIL: "pillow",
  sklearn: "scikit-learn",
  bs4: "beautifulsoup4",
  dateutil: "python-dateutil",
  dotenv: "python-dotenv",
  jwt: "pyjwt",
  psycopg2: "psycopg2-binary",
  google: "google-cloud-storage",
  zmq: "pyzmq",
  OpenSSL: "pyopenssl",
  Crypto: "pycryptodome",
  magic: "python-magic",
  serial: "pyserial",
  attr: "attrs",
  pkg_resources: "setuptools",
  skimage: "scikit-image",
  docx: "python-docx",
  telegram: "python-telegram-bot",
};

export const PY_STDLIB = new Set(
  (
    "__future__ abc argparse array ast asyncio atexit base64 binascii bisect builtins bz2 calendar cgi cmath cmd code codecs collections " +
    "colorsys concurrent configparser contextlib contextvars copy copyreg cProfile csv ctypes curses dataclasses datetime dbm decimal difflib " +
    "dis doctest email encodings enum errno faulthandler fcntl filecmp fileinput fnmatch fractions ftplib functools gc getopt getpass gettext " +
    "glob graphlib grp gzip hashlib heapq hmac html http imaplib importlib inspect io ipaddress itertools json keyword linecache locale logging " +
    "lzma mailbox marshal math mimetypes mmap multiprocessing netrc numbers operator optparse os pathlib pdb pickle pkgutil platform plistlib " +
    "poplib posixpath pprint profile pstats pty pwd queue quopri random re readline reprlib resource rlcompleter runpy sched secrets select " +
    "selectors shelve shlex shutil signal site smtplib socket socketserver sqlite3 ssl stat statistics string stringprep struct subprocess " +
    "symtable sys sysconfig syslog tabnanny tarfile tempfile termios textwrap threading time timeit tkinter token tokenize tomllib trace " +
    "traceback tracemalloc tty turtle types typing unicodedata unittest urllib uuid venv warnings wave weakref webbrowser winreg wsgiref " +
    "xml xmlrpc zipapp zipfile zipimport zlib zoneinfo"
  ).split(" ")
);
