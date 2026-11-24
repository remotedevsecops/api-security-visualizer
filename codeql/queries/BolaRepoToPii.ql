/**
 * @name BOLA 응답 PII 노출: 소유권 검사 없는 핸들러가 PII 담은 DTO를 반환
 * @description 요청자 컨텍스트를 받지 않는(= 소유권 검사 불가) 핸들러가
 *              email/name/phone 필드를 가진 응답 DTO를 생성·반환한다.
 *              BolaPathToRepo(식별자→DB 조회)와 결합하면 "DB 조회 → PII 응답"이 완성된다.
 *              (crAPI Java는 필드를 개별 getter로 꺼내 DTO에 넣어 순수 taint로는 getter에서 끊기므로,
 *               응답 DTO가 PII를 담는다는 사실은 구조적으로 확정한다.)
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @id apisec/bola-repo-to-pii
 * @tags security external/cwe/cwe-639
 */

import java

class HandlerMethod extends Method {
  HandlerMethod() { this.getAnAnnotation().getType().getName().matches("%Mapping") }
}

predicate isRequesterContextType(Type t) {
  t.(RefType).hasQualifiedName("javax.servlet.http", "HttpServletRequest") or
  t.(RefType).hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") or
  t.(RefType).getName() in ["Authentication", "Principal", "UserDetails"]
}

predicate handlerLacksRequester(HandlerMethod h) {
  not exists(Parameter p | p = h.getAParameter() and isRequesterContextType(p.getType()))
}

/** PII 필드를 가진 DTO 타입. */
class PiiDto extends Class {
  PiiDto() {
    this.getName().regexpMatch(".*(Response|Form|Dto|DTO)$") and
    this.getAField().getName().toLowerCase() in ["email", "fullname", "name", "phone", "number"]
  }

  string piiFields() {
    result =
      strictconcat(Field f |
        f = this.getAField() and
        f.getName().toLowerCase() in ["email", "fullname", "name", "phone", "number"]
      |
        f.getName(), ", "
      )
  }
}

/** 핸들러 h가 (직접 또는 서비스 호출을 통해) 메서드 m을 호출. 인터페이스 경유도 포함. */
predicate handlerReaches(HandlerMethod h, Callable m) {
  m = h or
  exists(Callable mid | handlerReaches(h, mid) |
    mid.calls(m) or
    // 인터페이스 선언 메서드를 호출하면 구현체도 도달한 것으로 간주
    exists(Method decl | mid.calls(decl) and m.(Method).overrides+(decl))
  )
}

/** 소유권 검사 없는 핸들러가, 흐름상 PII DTO를 생성해 반환. */
from HandlerMethod h, ClassInstanceExpr cie, PiiDto dto, Callable maker
where
  handlerLacksRequester(h) and
  cie.getConstructedType() = dto and
  cie.getEnclosingCallable() = maker and
  handlerReaches(h, maker)
select cie,
  "소유권 검사 없는 핸들러 " + h.getName() + "()의 응답에 PII(" + dto.piiFields() +
  ")가 담겨 반환됨 [handler=" + h.getName() + "]"
