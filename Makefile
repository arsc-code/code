lib:
	(cd arsc/k8s_util/lib && make)
	(cd ssa && make)

clean:
	(cd arsc/k8s_util/lib && make clean)
	(cd ssa && make)
