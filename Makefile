

dev-build: clean dev-build-pyi


dev-build-package:
	maturin develop

dev-build-pyi: dev-build-package
	pyo3-stubgen pykyber._pykyber ./python/

clean:
	rm ./python/pykyber/*.so
	rm ./python/pykyber/_pykyber.pyi
	rm -rf ./target/

benchmark:
	.venv/bin/python performance-tests/benchmark.py