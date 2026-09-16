# The local runtime as a container, for registries that start a server to
# look at its tools, and for anyone who would rather not install Python.
#
#   docker build -t aamio .
#   docker run -i -v aamio-home:/root/.aamio aamio
#
# The volume keeps the identity key and the inbox between runs; without it,
# every start is a fresh agent that has met nobody. The server speaks MCP on
# stdio, which is what -i is for. It makes its key on first start and opens an
# inbox at aamio.at, so no init step is needed.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
ENTRYPOINT ["aamio"]
CMD ["serve"]
