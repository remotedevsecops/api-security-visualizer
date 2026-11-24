/**
 * @name BOLA: path variable reaches repository lookup without owner context
 * @description Spring 핸들러의 @PathVariable 식별자가 소유권 검사 없이
 *              리포지토리 조회 인자까지 흘러간다. 핸들러가 요청자 컨텍스트
 *              (HttpServletRequest / Authentication / Principal)를 받지 않으면
 *              객체 소유권을 검증할 방법이 없다 → BOLA.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @id apisec/bola-pathvar-to-repo
 * @tags security external/cwe/cwe-639
 */

import java
import semmle.code.java.dataflow.TaintTracking

/** Spring 매핑 애너테이션이 붙은 핸들러 메서드. */
class HandlerMethod extends Method {
  HandlerMethod() {
    this.getAnAnnotation().getType().getName().matches("%Mapping")
  }
}

/** @PathVariable / @RequestParam 로 들어오는 핸들러 파라미터 (사용자 제어 식별자). */
class PathVarParam extends Parameter {
  HandlerMethod handler;
  PathVarParam() {
    this = handler.getAParameter() and
    this.getAnAnnotation().getType().getName() in ["PathVariable", "RequestParam"]
  }
  HandlerMethod getHandler() { result = handler }
}

/** 요청자 신원을 담는 타입 — 이게 핸들러 파라미터에 있으면 소유권 검사가 가능. */
predicate isRequesterContextType(Type t) {
  t.(RefType).hasQualifiedName("javax.servlet.http", "HttpServletRequest") or
  t.(RefType).hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") or
  t.(RefType).getName() in ["Authentication", "Principal", "UserDetails"]
}

/** 요청자 컨텍스트를 전혀 받지 않는 핸들러 → 소유권 검사 불가 구조. */
predicate handlerLacksRequester(HandlerMethod h) {
  not exists(Parameter p | p = h.getAParameter() and isRequesterContextType(p.getType()))
}

/** 리포지토리/DAO 조회 호출의 인자 (sink 후보): findBy*, getBy*, findById 등. */
class RepoLookupArg extends Expr {
  RepoLookupArg() {
    exists(MethodCall mc |
      mc.getMethod().getName().regexpMatch("(?i)(find|get|read|load|query|select).*") and
      (
        mc.getMethod().getDeclaringType().getName().matches("%Repository") or
        mc.getMethod().getDeclaringType().getName().matches("%Dao") or
        mc.getMethod().getName().matches("findBy%") or
        mc.getMethod().getName() = "findByUuid"
      ) and
      this = mc.getAnArgument()
    )
  }
}

module BolaConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(PathVarParam p |
      src.asParameter() = p and
      handlerLacksRequester(p.getHandler())
    )
  }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof RepoLookupArg }
}

module BolaFlow = TaintTracking::Global<BolaConfig>;

import BolaFlow::PathGraph

/** source 파라미터가 속한 핸들러 메서드. */
Method sourceHandler(BolaFlow::PathNode source) {
  result = source.getNode().asParameter().(PathVarParam).getHandler()
}

from BolaFlow::PathNode source, BolaFlow::PathNode sink, Method handler
where BolaFlow::flowPath(source, sink) and handler = sourceHandler(source)
select sink.getNode(), source, sink,
  "소유권 검사 없는 @PathVariable이 " + handler.getName() +
  "() 핸들러에서 리포지토리 조회까지 도달 (요청자 컨텍스트 없음) [handler=" + handler.getName() + "]",
  source.getNode(), source.getNode().toString()
