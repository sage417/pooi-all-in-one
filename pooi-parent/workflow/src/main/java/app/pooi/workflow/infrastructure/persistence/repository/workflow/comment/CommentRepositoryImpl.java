package app.pooi.workflow.infrastructure.persistence.repository.workflow.comment;

import app.pooi.workflow.domain.model.workflow.comment.Comment;
import app.pooi.workflow.domain.repository.CommentRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.comment.CommentConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.comment.CommentEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.comment.CommentEntityMapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Repository
@RequiredArgsConstructor
class CommentRepositoryImpl extends ServiceImpl<CommentEntityMapper, CommentEntity> implements CommentRepository {

    private static final ThreadLocal<Deque<CommentEntity>> TRANSACTIONAL_COMMENT_ENTITY_HOLDER = ThreadLocal.withInitial(ArrayDeque::new);

    private final CommentConverter converter;

    @Override
    public boolean save(Comment comment, boolean flushCache) {
        Deque<CommentEntity> deque = TRANSACTIONAL_COMMENT_ENTITY_HOLDER.get();
        CommentEntity commentEntity = converter.toEntity(comment);

        if (flushCache) {
            super.save(commentEntity);
            deque.forEach(super::save);
            TRANSACTIONAL_COMMENT_ENTITY_HOLDER.remove();
        } else {
            // cache first time
            if (deque.isEmpty()) {
                TransactionSynchronizationManager.registerSynchronization(new CommentCacheTransactionSynchronization());
            }
            deque.push(commentEntity);
        }
        return true;
    }

    @Override
    public List<Comment> listByInstanceId(String processInstanceId) {
        List<CommentEntity> commentEntities = getBaseMapper().selectList(Wrappers.lambdaQuery(CommentEntity.class)
                .eq(CommentEntity::getProcessInstanceId, processInstanceId));
        return commentEntities.stream().map(converter::toModel).collect(Collectors.toList());
    }

    private class CommentCacheTransactionSynchronization implements TransactionSynchronization {
        @Override
        public void beforeCommit(boolean readOnly) {

            Deque<CommentEntity> deque = TRANSACTIONAL_COMMENT_ENTITY_HOLDER.get();
            try {
                if (!readOnly && !deque.isEmpty()) {
                    // FALL BACK didnt flush before commit
                    deque.forEach(CommentRepositoryImpl.super::save);
                }
            } finally {
                TRANSACTIONAL_COMMENT_ENTITY_HOLDER.remove();
            }
        }

        @Override
        public void afterCompletion(int status) {
            TRANSACTIONAL_COMMENT_ENTITY_HOLDER.remove();
        }
    }
}
