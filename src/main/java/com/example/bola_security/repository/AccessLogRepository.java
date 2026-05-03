package com.example.bola_security.repository;
import java.time.LocalDateTime;
import java.util.*;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.example.bola_security.model.AccessLog;
@Repository
public interface AccessLogRepository extends JpaRepository<AccessLog,Long>{
    List<AccessLog> findByUserIdAndTimestampAfter(Long userId, LocalDateTime time);

    @Query("""
            select count(distinct log.resourceId)
            from AccessLog log
            where log.userId = :userId
            and log.timestamp >= :after
            """)
    long countDistinctResourceIdsSince(@Param("userId") Long userId, @Param("after") LocalDateTime after);

    List<AccessLog> findTop50ByOrderByTimestampDesc();
}
