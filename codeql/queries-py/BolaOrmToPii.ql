/**
 * @name BOLA/무인증: ORM 조회 객체가 소유권 검사 없이 PII 직렬화로 흐름
 * @description 인증 데코레이터(@jwt_auth_required)가 없는 Django 뷰 메서드에서
 *              Model.objects.get(...) 으로 조회한 객체가 소유권 검사 없이
 *              UserSerializer 등 PII 직렬화 호출까지 흘러간다.
 *              → 무인증 + BOLA + 개인정보 유출이 한 흐름에.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @id apisec/bola-orm-to-pii
 * @tags security external/cwe/cwe-639 external/cwe/cwe-306
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

/** 인증 데코레이터가 붙지 않은 뷰 메서드. */
predicate unauthViewMethod(Function f) {
  f.getName() in ["get", "post", "put", "delete"] and
  f.getLocation().getFile().getBaseName() = "views.py" and
  not exists(Expr d | d = f.getADecorator() | d.toString().matches("%auth%"))
}

/** Model.objects.get/filter(...) 호출 — ORM 조회 (소스). */
predicate ormLookup(DataFlow::CallCfgNode call) {
  exists(string m | m in ["get", "filter", "first", "all"] |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = m and
    call.getFunction().(DataFlow::AttrRead).getObject().(DataFlow::AttrRead).getAttributeName() = "objects"
  )
}

/** *Serializer(obj) 호출의 인자 — PII 직렬화 (싱크). */
predicate piiSerializer(DataFlow::Node arg) {
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::Node).asExpr().(Name).getId().matches("%Serializer") and
    arg = call.getArg(0)
  )
}

module BolaPiiConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(DataFlow::CallCfgNode call, Function f |
      ormLookup(call) and src = call and
      call.getScope() = f and unauthViewMethod(f)
    )
  }

  predicate isSink(DataFlow::Node sink) { piiSerializer(sink) }
}

module BolaPiiFlow = TaintTracking::Global<BolaPiiConfig>;

import BolaPiiFlow::PathGraph

from BolaPiiFlow::PathNode source, BolaPiiFlow::PathNode sink, Function f
where
  BolaPiiFlow::flowPath(source, sink) and
  f = source.getNode().(DataFlow::CallCfgNode).getScope()
select sink.getNode(), source, sink,
  "무인증 뷰 " + f.getName() + "()에서 ORM 조회 객체가 소유권 검사 없이 PII 직렬화까지 도달 [handler=" +
  f.getQualifiedName() + "]",
  source.getNode(), "ORM 조회"
